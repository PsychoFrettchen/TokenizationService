using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace TokenizationService.Authorization
{
    /// <summary>
    ///     Interface for an access token validator.
    ///     An implementation is expected to validate a JWT (e.g., issued by Keycloak)
    ///     and extract the list of valid scopes (permissions) from it.
    /// </summary>
    public interface IAccessTokenValidator
    {
        /// <summary>
        ///     Validates the specified Bearer token and returns the contained scopes.
        ///     Throws an RpcException if the token is invalid.
        /// </summary>
        Task<IReadOnlyCollection<string>> ValidateAsync(string bearerToken);
    }

    /// <summary>
    ///     gRPC server interceptor responsible for method-level authorization.
    ///     Responsibilities:
    ///     - Reads the Bearer token from the gRPC headers.
    ///     - Validates the token via IAccessTokenValidator.
    ///     - Verifies that the invoked method has the required scopes.
    ///     This interceptor is automatically executed for every incoming RPC call.
    /// </summary>
    public sealed class AuthorizationInterceptor : Interceptor
    {
        /// <summary>
        ///     Defines which gRPC methods require which scopes (permissions).
        ///     The key is the fully qualified method name
        ///     (e.g., "tokenization.v1.TokenizationService/Tokenize").
        ///     The value is an array of acceptable permissions,
        ///     where at least one must be present.
        /// </summary>
        private static readonly Dictionary<string, string[]> requiredScopes =
            new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["tokenization.v1.TokenizationService/Tokenize"] = new[] { "tokenize" },
                ["tokenization.v1.TokenizationService/StreamTokenize"] = new[] { "tokenize" },
                ["tokenization.v1.TokenizationService/Detokenize"] = new[] { "detokenize" },
                ["tokenization.v1.TokenizationService/ValidateToken"] = new[] { "tokenize", "detokenize" },
                ["tokenization.v1.TokenizationService/RotateKey"] = new[] { "admin" }
            };

        private readonly IAccessTokenValidator _validator;

        public AuthorizationInterceptor(IAccessTokenValidator validator)
        {
            _validator = validator;
        }

        /// <summary>
        ///     Extracts the Bearer token from the gRPC "authorization" header.
        ///     Validates its structure (must contain "Bearer ...").
        /// </summary>
        private static string GetBearerToken(ServerCallContext ctx)
        {
            var auth = ctx.RequestHeaders?.FirstOrDefault(h =>
                string.Equals(h.Key, "authorization", StringComparison.OrdinalIgnoreCase));

            if (auth == null || string.IsNullOrWhiteSpace(auth.Value))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Missing Authorization header"));

            if (!auth.Value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Authorization must use Bearer scheme"));

            // Return only the token portion (without "Bearer ")
            return auth.Value.Substring("Bearer ".Length).Trim();
        }

        /// <summary>
        ///     Ensures that the user possesses at least one of the scopes required for the method.
        ///     If not, a gRPC PermissionDenied error is thrown.
        /// </summary>
        private static void DemandScopes(string method, IReadOnlyCollection<string> userScopes)
        {
            // If the method does not require specific scopes → no validation needed
            if (!requiredScopes.TryGetValue(method, out var needed))
                return;

            // Access granted if the user has at least one required scope
            if (needed.Any(ns => userScopes.Contains(ns, StringComparer.Ordinal)))
                return;

            // Otherwise → insufficient permissions
            throw new RpcException(
                new Status(StatusCode.PermissionDenied,
                    $"Missing required scope: {string.Join(" OR ", needed)}"));
        }

        // ----------------------------------------------------------------------
        // The following methods override the default gRPC pipeline.
        // For each RPC type (Unary, Streaming, etc.), token validation is enforced.
        // ----------------------------------------------------------------------

        /// <summary>
        ///     Executed for simple Unary RPC calls (Request → Response).
        /// </summary>
        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            // Extract and validate token
            var token = GetBearerToken(context);
            var scopes = await _validator.ValidateAsync(token).ConfigureAwait(false);

            // Check authorization for the invoked method
            DemandScopes(context.Method, scopes);

            // If everything is valid → execute the actual method
            return await continuation(request, context).ConfigureAwait(false);
        }

        /// <summary>
        ///     Executed for Server-Streaming RPCs
        ///     (client sends one request, server streams multiple responses).
        /// </summary>
        public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
            TRequest request,
            IServerStreamWriter<TResponse> responseStream,
            ServerCallContext context,
            ServerStreamingServerMethod<TRequest, TResponse> continuation)
        {
            var token = GetBearerToken(context);
            var scopes = await _validator.ValidateAsync(token).ConfigureAwait(false);
            DemandScopes(context.Method, scopes);
            await continuation(request, responseStream, context).ConfigureAwait(false);
        }

        /// <summary>
        ///     Executed for Client-Streaming RPCs
        ///     (client streams multiple requests, server sends one response).
        /// </summary>
        public override async Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(
            IAsyncStreamReader<TRequest> requestStream,
            ServerCallContext context,
            ClientStreamingServerMethod<TRequest, TResponse> continuation)
        {
            var token = GetBearerToken(context);
            var scopes = await _validator.ValidateAsync(token).ConfigureAwait(false);
            DemandScopes(context.Method, scopes);
            return await continuation(requestStream, context).ConfigureAwait(false);
        }

        /// <summary>
        ///     Executed for Duplex-Streaming RPCs
        ///     (both client and server stream data simultaneously).
        /// </summary>
        public override async Task DuplexStreamingServerHandler<TRequest, TResponse>(
            IAsyncStreamReader<TRequest> requestStream,
            IServerStreamWriter<TResponse> responseStream,
            ServerCallContext context,
            DuplexStreamingServerMethod<TRequest, TResponse> continuation)
        {
            var token = GetBearerToken(context);
            var scopes = await _validator.ValidateAsync(token).ConfigureAwait(false);
            DemandScopes(context.Method, scopes);
            await continuation(requestStream, responseStream, context).ConfigureAwait(false);
        }
    }
}