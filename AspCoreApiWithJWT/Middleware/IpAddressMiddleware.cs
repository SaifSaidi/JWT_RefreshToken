namespace AspCoreApiWithJWT.Middleware
{
    public class IpAddressMiddleware
    {
        private readonly RequestDelegate _next;

        public IpAddressMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var ipAddress = GetIpAddress(context);
            context.Items["IpAddress"] = ipAddress;
            await _next(context);
        }

        private string GetIpAddress(HttpContext context)
        {
            if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
            {
                return forwardedFor.ToString();
            }
            return context.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "unknown";
        }
    }
}
