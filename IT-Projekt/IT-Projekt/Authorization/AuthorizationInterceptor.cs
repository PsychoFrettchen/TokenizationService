using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace IT_Projekt.Authorization
{
    /// <summary>
    /// Schnittstelle für einen Access-Token-Validator.
    /// Erwartet wird eine Implementierung, die ein JWT (z. B. von Keycloak) prüft
    /// und daraus eine Liste gültiger Scopes (Berechtigungen) extrahiert.
    /// </summary>
    public interface IAccessTokenValidator
    {
        /// <summary>
        /// Prüft das angegebene Bearer-Token auf Gültigkeit und gibt die enthaltenen Scopes zurück.
        /// Wirft eine RpcException, falls das Token ungültig ist.
        /// </summary>
        Task<IReadOnlyCollection<string>> ValidateAsync(string bearerToken);
    }

    /// <summary>
    /// gRPC-Serverinterceptor zur Autorisierung von Methodenaufrufen.
    /// 
    /// Aufgaben:
    ///  - Liest das Bearer-Token aus den gRPC-Headern.
    ///  - Validiert das Token über IAccessTokenValidator.
    ///  - Prüft, ob die aufgerufene Methode die erforderlichen Scopes besitzt.
    /// 
    /// Wird automatisch bei jedem eingehenden RPC-Aufruf aufgerufen.
    /// </summary>
    public sealed class AuthorizationInterceptor : Interceptor
    {
        private readonly IAccessTokenValidator _validator;

        /// <summary>
        /// Definiert, welche gRPC-Methoden welche Scopes (Berechtigungen) erfordern.
        /// Der Key ist der vollständige Methodenname (z. B. "tokenization.v1.TokenizationService/Tokenize").
        /// Der Wert ist ein String-Array mit allen möglichen Berechtigungen, von denen mindestens eine erforderlich ist.
        /// </summary>
        private static readonly Dictionary<string, string[]> requiredScopes =
            new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["tokenization.v1.TokenizationService/Tokenize"] = new[] { "tokenize" },
                ["tokenization.v1.TokenizationService/StreamTokenize"] = new[] { "tokenize" },
                ["tokenization.v1.TokenizationService/Detokenize"] = new[] { "detokenize" },
                ["tokenization.v1.TokenizationService/ValidateToken"] = new[] { "tokenize", "detokenize" },
                ["tokenization.v1.TokenizationService/RotateKey"] = new[] { "admin" },
            };

        public AuthorizationInterceptor(IAccessTokenValidator validator) => _validator = validator;

        /// <summary>
        /// Extrahiert das Bearer-Token aus dem gRPC-Header "authorization".
        /// Validiert die Struktur (muss "Bearer ..." enthalten).
        /// </summary>
        private static string GetBearerToken(ServerCallContext ctx)
        {
            var auth = ctx.RequestHeaders?.FirstOrDefault(h =>
                string.Equals(h.Key, "authorization", StringComparison.OrdinalIgnoreCase));

            if (auth == null || string.IsNullOrWhiteSpace(auth.Value))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Missing Authorization header"));

            if (!auth.Value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Authorization must be Bearer"));

            // Gibt nur den Token-Teil zurück (ohne "Bearer ")
            return auth.Value.Substring("Bearer ".Length).Trim();
        }

        /// <summary>
        /// Prüft, ob der Benutzer mindestens einen der für die Methode erforderlichen Scopes besitzt.
        /// Falls nicht, wird eine gRPC PermissionDenied-Fehlermeldung ausgelöst.
        /// </summary>
        private static void DemandScopes(string method, IReadOnlyCollection<string> userScopes)
        {
            // Wenn die Methode keine speziellen Scopes erfordert → kein Check nötig
            if (!requiredScopes.TryGetValue(method, out var needed))
                return;

            // Zugriff erlaubt, wenn Benutzer mindestens einen geforderten Scope besitzt
            if (needed.Any(ns => userScopes.Contains(ns, StringComparer.Ordinal)))
                return;

            // Andernfalls → keine ausreichende Berechtigung
            throw new RpcException(
                new Status(StatusCode.PermissionDenied,
                $"Missing required scope: {string.Join(" OR ", needed)}"));
        }

        // ----------------------------------------------------------------------
        // Die folgenden Methoden überschreiben die Standard-gRPC-Pipeline.
        // Für jeden RPC-Typ (Unary, Streaming etc.) wird der Tokencheck eingebaut.
        // ----------------------------------------------------------------------

        /// <summary>
        /// Wird bei einfachen Unary-RPC-Aufrufen (Request → Response) ausgeführt.
        /// </summary>
        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            // Token auslesen & prüfen
            var token = GetBearerToken(context);
            var scopes = await _validator.ValidateAsync(token).ConfigureAwait(false);

            // Autorisierung für die Methode prüfen
            DemandScopes(context.Method, scopes);

            // Wenn alles OK → tatsächliche Methode ausführen
            return await continuation(request, context).ConfigureAwait(false);
        }

        /// <summary>
        /// Wird bei Server-Streaming-RPCs (Client sendet Request, Server streamt mehrere Responses) ausgeführt.
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
        /// Wird bei Client-Streaming-RPCs (Client streamt Requests, Server sendet eine Antwort) ausgeführt.
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
        /// Wird bei Duplex-Streaming-RPCs ausgeführt (beide Seiten streamen Daten gleichzeitig).
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
