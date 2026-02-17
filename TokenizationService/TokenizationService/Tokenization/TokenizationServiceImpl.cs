using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using em.Tokenization.V1;
using Grpc.Core;
using TokenizationService.CryptoImpl;
using TokenizationService.Provider;

namespace TokenizationService.Tokenization
{
    /// <summary>
    ///     gRPC implementation of the Tokenization service.
    ///     Responsibilities:
    ///     <list type="bullet">
    ///         <item>
    ///             <description>Tokenization (Random/Hash/HMAC/FPE/Encrypted)</description>
    ///         </item>
    ///         <item>
    ///             <description>Detokenization (via store or via FPE/encryption)</description>
    ///         </item>
    ///         <item>
    ///             <description>Key rotation (determine active KeyId per tenant)</description>
    ///         </item>
    ///         <item>
    ///             <description>Streaming tokenization (one init, many items)</description>
    ///         </item>
    ///     </list>
    ///     Dependencies:
    ///     <list type="bullet">
    ///         <item>
    ///             <description><see cref="IKeyProvider" />: provides/manages keys (e.g., Vault)</description>
    ///         </item>
    ///         <item>
    ///             <description><see cref="ITokenStore" />: persists reversible tokens (e.g., RANDOM) for detokenization</description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 <see cref="IFpeEngine" />: optional FPE algorithm (FF1/FF3-1); may be <c>null</c>
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    public sealed class TokenizationServiceImpl : em.Tokenization.V1.TokenizationService.TokenizationServiceBase
    {
        private const int AesKeyLen = 32;
        private readonly IFpeEngine fpe; // may be null → FPE operations are disabled

        private readonly IKeyProvider keys;
        private readonly ITokenStore store;
        private readonly bool storeNonReversible; // optional: also store HASH/HMAC (policy)

        /// <summary>
        ///     Creates a new service instance.
        /// </summary>
        /// <param name="keys">Key provider (e.g., VaultKeyProvider)</param>
        /// <param name="store">Token store for reversible tokens (e.g., VaultHttpTokenStore)</param>
        /// <param name="fpe">FPE engine (may be null; then FPE calls are not allowed)</param>
        /// <param name="storeNonReversible">If true, HASH/HMAC are also stored (detokenization via store possible)</param>
        public TokenizationServiceImpl(IKeyProvider keys, ITokenStore store, IFpeEngine fpe,
            bool storeNonReversible = false)
        {
            this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
            this.store = store ?? throw new ArgumentNullException(nameof(store));
            this.fpe = fpe;
            this.storeNonReversible = storeNonReversible;
        }

        // ----------------- Unary -----------------

        /// <summary>
        ///     Performs tokenization for a list of fields.
        /// </summary>
        /// <exception cref="RpcException">InvalidArgument for malformed requests</exception>
        public override Task<TokenizeResponse> Tokenize(TokenizeRequest request, ServerCallContext context)
        {
            if (request == null) throw new RpcException(new Status(StatusCode.InvalidArgument, "Request is null"));
            if (request.Items == null || request.Items.Count == 0)
                throw new RpcException(new Status(StatusCode.InvalidArgument, "No items to tokenize"));

            var resp = new TokenizeResponse
            {
                // Determine effective KeyId once and include it in the response
                KeyId = EffectiveKeyId(request.Context, keys)
            };

            foreach (var fp in request.Items)
                try
                {
                    var token = TokenizeOne(fp, request.TokenType, request.Context, resp.KeyId);
                    resp.Items.Add(new TokenizedField { Field = fp.Field ?? "", Token = token });

                    // Persist reversible types if needed (RANDOM always; HMAC/HASH depending on policy)
                    if (ShouldPersist(request.TokenType))
                        store.Save(new TokenRecord
                        {
                            Token = token,
                            TenantId = request.Context?.TenantId ?? "",
                            Field = fp.Field ?? "",
                            Plaintext = fp.Plaintext ?? "",
                            Type = request.TokenType,
                            KeyId = resp.KeyId ?? "",
                            DataClass = fp.DataClass,
                            Attributes = fp.Attributes
                        });
                }
                catch (Exception ex)
                {
                    // Collect per-field errors instead of aborting globally
                    resp.Errors.Add(new FieldError
                    {
                        Field = fp?.Field ?? "",
                        Code = 50001,
                        Message = $"Tokenization failed: {ex.Message}"
                    });
                }

            return Task.FromResult(resp);
        }

        /// <summary>
        ///     Performs detokenization.
        ///     First consults the token store; if nothing is found there, the service
        ///     attempts a cryptographic reversal depending on type (FPE/Encrypted).
        /// </summary>
        public override Task<DetokenizeResponse> Detokenize(DetokenizeRequest request, ServerCallContext context)
        {
            if (request == null) throw new RpcException(new Status(StatusCode.InvalidArgument, "Request is null"));
            if (request.Items == null || request.Items.Count == 0)
                throw new RpcException(new Status(StatusCode.InvalidArgument, "No items to detokenize"));

            var resp = new DetokenizeResponse
            {
                KeyId = EffectiveKeyId(request.Context, keys)
            };

            foreach (var item in request.Items)
                try
                {
                    if (TryDetokenizeOne(item, request.Context, resp.KeyId, out var plaintext))
                        resp.Items.Add(new DetokenizedField { Field = item.Field ?? "", Plaintext = plaintext ?? "" });
                    else
                        resp.Errors.Add(new FieldError
                        {
                            Field = item.Field ?? "", Code = 40404,
                            Message = "Token not found or not reversible with current policy."
                        });
                }
                catch (Exception ex)
                {
                    resp.Errors.Add(new FieldError
                        { Field = item.Field ?? "", Code = 50002, Message = $"Detokenization failed: {ex.Message}" });
                }

            return Task.FromResult(resp);
        }

        /// <summary>
        ///     Validates the structure of a token and returns (if available) metadata from the store
        ///     (field name, DataClass, KeyId).
        /// </summary>
        public override Task<ValidateTokenResponse> ValidateToken(ValidateTokenRequest request,
            ServerCallContext context)
        {
            var v = new ValidateTokenResponse { Valid = false, TokenType = TokenType.Unspecified };

            if (TokenWire.TryParse(request?.Token, out var typeTag, out _, out _))
            {
                v.Valid = true;
                v.TokenType = ParseType(typeTag);
                // Determine default KeyId; if present in the store we overwrite it later
                v.KeyId = request?.Context?.KeyId ?? keys.GetActiveKeyId(request?.Context?.TenantId ?? "");

                if (store.TryGet(request.Token, out var rec))
                {
                    v.Field = rec.Field ?? "";
                    v.DataClass = rec.DataClass;
                    v.KeyId = rec.KeyId;
                }
            }

            return Task.FromResult(v);
        }

        /// <summary>
        ///     Optionally sets a new active KeyId for the tenant and returns the (new) active KeyId.
        /// </summary>
        public override Task<RotateKeyResponse> RotateKey(RotateKeyRequest request, ServerCallContext context)
        {
            var tenant = request?.Context?.TenantId ?? "";
            if (!string.IsNullOrEmpty(request?.NewKeyId))
                keys.Rotate(tenant, request.NewKeyId);

            return Task.FromResult(new RotateKeyResponse { ActiveKeyId = keys.GetActiveKeyId(tenant) });
        }

        // --------------- Streaming ----------------

        /// <summary>
        ///     Bidirectional streaming:
        ///     The first message must contain <see cref="StreamTokenizeInit" /> (type &amp; context),
        ///     followed by any number of items; for each item, a result is written back immediately.
        /// </summary>
        public override async Task StreamTokenize(IAsyncStreamReader<StreamTokenizeIn> requestStream,
            IServerStreamWriter<StreamTokenizeOut> responseStream,
            ServerCallContext context)
        {
            var initialized = false;
            var tokenType = TokenType.Unspecified;
            Context ctx = null;
            string keyId = null;

            while (await requestStream.MoveNext().ConfigureAwait(false))
            {
                var msg = requestStream.Current;
                if (!initialized)
                {
                    if (msg?.Init == null)
                        throw new RpcException(new Status(StatusCode.InvalidArgument, "First message must be init."));

                    initialized = true;
                    tokenType = msg.Init.TokenType;
                    ctx = msg.Init.Context ?? new Context();
                    keyId = EffectiveKeyId(ctx, keys);
                    continue;
                }

                if (msg.Item == null) continue;

                try
                {
                    var tok = TokenizeOne(new FieldPayload
                    {
                        Field = msg.Item.Field,
                        Plaintext = msg.Item.Plaintext,
                        DataClass = msg.Item.DataClass,
                        PreserveFormat = msg.Item.PreserveFormat,
                        FormatMode = msg.Item.FormatMode,
                        FormatMask = msg.Item.FormatMask,
                        Attributes = { msg.Item.Attributes }
                    }, tokenType, ctx, keyId);

                    if (ShouldPersist(tokenType))
                        store.Save(new TokenRecord
                        {
                            Token = tok,
                            TenantId = ctx?.TenantId ?? "",
                            Field = msg.Item.Field ?? "",
                            Plaintext = msg.Item.Plaintext ?? "",
                            Type = tokenType,
                            KeyId = keyId ?? "",
                            DataClass = msg.Item.DataClass,
                            Attributes = msg.Item.Attributes
                        });

                    await responseStream.WriteAsync(new StreamTokenizeOut
                    {
                        Item = new TokenizedField { Field = msg.Item.Field ?? "", Token = tok }
                    }).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    await responseStream.WriteAsync(new StreamTokenizeOut
                    {
                        Error = new FieldError { Field = msg.Item.Field ?? "", Code = 50011, Message = ex.Message }
                    }).ConfigureAwait(false);
                }
            }
        }

        // ------------------------------------------
        // ============== Core helpers ===============
        // ------------------------------------------

        /// <summary>
        ///     Determines the effective KeyId to use:
        ///     if set in the context → use it; otherwise use the active KeyId from the <see cref="IKeyProvider" />.
        /// </summary>
        private static string EffectiveKeyId(Context ctx, IKeyProvider keys)
        {
            var tenant = ctx?.TenantId ?? "";
            return !string.IsNullOrEmpty(ctx?.KeyId) ? ctx.KeyId : keys.GetActiveKeyId(tenant);
        }

        /// <summary>
        ///     Policy: which token types are additionally persisted in the store?
        /// </summary>
        private bool ShouldPersist(TokenType type)
        {
            switch (type)
            {
                case TokenType.Random: return true; // RANDOM is only reversible this way
                case TokenType.Hmac:
                case TokenType.Hash: return storeNonReversible; // optional depending on policy
                case TokenType.Fpe: return false; // reversible via IFpeEngine
                case TokenType.Encrypted:
                default: return false;
            }
        }

        /// <summary>
        ///     Converts the type tag from the token into the protobuf enum.
        /// </summary>
        private TokenType ParseType(string tag)
        {
            switch (tag)
            {
                case "r": return TokenType.Random;
                case "f": return TokenType.Fpe;
                case "hc": return TokenType.Hmac;
                case "hs": return TokenType.Hash;
                case "e": return TokenType.Encrypted;
                default: return TokenType.Unspecified;
            }
        }

        /// <summary>
        ///     Derives a suitable alphabet domain from <see cref="FieldPayload.DataClass" />
        ///     (e.g., digits only for card numbers).
        /// </summary>
        private static string InferAlphabet(FieldPayload fp)
        {
            switch (fp.DataClass)
            {
                case DataClass.CreditCard:
                case DataClass.Iban:
                case DataClass.Phone:
                case DataClass.Ssn:
                case DataClass.PostalCode:
                case DataClass.Date:
                    return Alphabets.Digits;
                default:
                    return Alphabets.Alnum;
            }
        }

        /// <summary>
        ///     Fallback: infer the alphabet based on field name
        ///     (for detokenization of FPE tokens without a DataClass).
        /// </summary>
        private static string InferAlphabetFromField(string field)
        {
            if (string.IsNullOrEmpty(field)) return Alphabets.Alnum;
            var f = field.ToLowerInvariant();
            if (f.Contains("card") || f.Contains("iban") || f.Contains("phone") || f.Contains("ssn") ||
                f.Contains("zip") || f.Contains("postal"))
                return Alphabets.Digits;
            return Alphabets.Alnum;
        }

        /// <summary>
        ///     Tokenizes exactly one field, including per-field key derivation (HKDF) (tenant/kid/field).
        /// </summary>
        private string TokenizeOne(FieldPayload fp, TokenType type, Context ctx, string keyId)
        {
            if (fp == null) throw new ArgumentNullException(nameof(fp));

            var tenant = ctx?.TenantId ?? "";
            var masterKey = keys.GetKey(tenant, keyId);
            if (masterKey == null || masterKey.Length == 0)
                throw new InvalidOperationException("Key provider returned no key material");

            // Derive a field key (HKDF) with context binding
            var tweak = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
            var purpose = Encoding.UTF8.GetBytes(ctx?.Purpose ?? "");
            var info = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={fp.Field}");
            var derived = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

            switch (type)
            {
                case TokenType.Random:
                {
                    // Only reversible via store (saved in Tokenize())
                    var payload = Crypto.Base64Url(Crypto.RandomBytes(16));
                    return TokenWire.Build("r", keyId, payload);
                }

                case TokenType.Hash:
                {
                    var hex = Crypto.Sha256Hex(fp.Plaintext ?? "");
                    var token = TokenWire.Build("hs", keyId, hex);
                    return ApplyMaskedViewIfRequested(token, fp, derived);
                }

                case TokenType.Hmac:
                {
                    var hex = Crypto.HmacSha256Hex(fp.Plaintext ?? "", derived);
                    var token = TokenWire.Build("hc", keyId, hex);
                    return ApplyMaskedViewIfRequested(token, fp, derived);
                }

                case TokenType.Fpe:
                {
                    if (fpe == null)
                        throw new RpcException(new Status(StatusCode.FailedPrecondition,
                            "FPE not configured. Provide an IFpeEngine."));

                    var alphabet = InferAlphabet(fp);
                    var cipher = fpe.Encrypt(fp.Plaintext ?? "", derived, tweak, alphabet);

                    // For digit-only domains embed as digits if possible, otherwise Base64Url
                    var payload = alphabet == Alphabets.Digits && cipher.All(char.IsDigit)
                        ? cipher
                        : Crypto.Base64Url(Encoding.UTF8.GetBytes(cipher));

                    return TokenWire.Build("f", keyId, payload);
                }

                case TokenType.Encrypted:
                {
                    var ct = AesGcmBc.Encrypt(derived, Encoding.UTF8.GetBytes(fp.Plaintext ?? ""));
                    var blob = AesGcmBc.Pack(ct);
                    return TokenWire.Build("e", keyId, Crypto.Base64Url(blob));
                }

                default:
                    throw new RpcException(new Status(StatusCode.InvalidArgument, $"Unsupported TokenType: {type}"));
            }
        }

        /// <summary>
        ///     Attempts to reverse a token (Store → FPE/Encrypted).
        /// </summary>
        private bool TryDetokenizeOne(TokenizedField item, Context ctx, string keyId, out string plaintext)
        {
            plaintext = null;

            // 1) Store hit?
            if (store.TryGet(item.Token, out var rec))
            {
                plaintext = rec.Plaintext;
                return true;
            }

            // 2) Parse token (to determine type/payload)
            if (!TokenWire.TryParse(item.Token, out var typeTag, out _, out var payload))
                return false;

            // 3) Cryptographic reversal depending on type
            if (typeTag == "f")
            {
                if (fpe == null) return false;

                var tenant = ctx?.TenantId ?? "";
                var masterKey = keys.GetKey(tenant, keyId);
                var tweak = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
                var info = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={item.Field}");
                var derived = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

                var alphabet = InferAlphabetFromField(item.Field);
                var cipher = alphabet == Alphabets.Digits && payload.All(char.IsDigit)
                    ? payload
                    : Encoding.UTF8.GetString(Crypto.FromBase64Url(payload));

                plaintext = fpe.Decrypt(cipher, derived, tweak, alphabet);
                return true;
            }

            if (typeTag == "e")
            {
                var tenant = ctx?.TenantId ?? "";
                var masterKey = keys.GetKey(tenant, keyId);
                var tweak = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
                var info = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={item.Field}");
                var derived = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

                var blob = Crypto.FromBase64Url(payload);
                AesGcmBc.Unpack(blob, out var nonce, out var tag, out var ciphertext);
                var ptBytes = AesGcmBc.Decrypt(derived, nonce, ciphertext, tag);
                plaintext = Encoding.UTF8.GetString(ptBytes);
                return true;
            }

            return false;
        }

        /// <summary>
        ///     If requested, generates a deterministic formatted view (<see cref="FormatMode.Masked" />)
        ///     and appends it as a suffix <c>~{view}</c> to the token.
        /// </summary>
        private static string ApplyMaskedViewIfRequested(string token, FieldPayload fp, byte[] derived)
        {
            if (fp.FormatMode == FormatMode.Masked && !string.IsNullOrEmpty(fp.FormatMask))
            {
                var seed = Crypto.Hkdf(derived, null, Encoding.UTF8.GetBytes("view/mask:" + (fp.Plaintext ?? "")), 32);
                var view = FormatShim.DeterministicMaskedView(fp.FormatMask, seed);
                return $"{token}~{view}";
            }

            return token;
        }
    }
}