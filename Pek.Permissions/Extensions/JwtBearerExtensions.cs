using Microsoft.AspNetCore.Authentication;

using Pek.Permissions.Identity.JwtBearer.Internal;
using Pek.Permissions.Identity.Options;

namespace Pek.Permissions.Extensions;

public static class JwtBearerExtensions
{
    public static AuthenticationBuilder AddPekJwtBearer(this AuthenticationBuilder builder)
    {
        return builder.AddPekJwtBearer("Bearer", delegate
        {
        });
    }

    public static AuthenticationBuilder AddPekJwtBearer(this AuthenticationBuilder builder, string authenticationScheme)
    {
        return builder.AddPekJwtBearer(authenticationScheme, delegate
        {
        });
    }

    public static AuthenticationBuilder AddPekJwtBearer(this AuthenticationBuilder builder, Action<PekJwtBearerOptions> configureOptions)
    {
        return builder.AddPekJwtBearer("Bearer", configureOptions);
    }

    public static AuthenticationBuilder AddPekJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<PekJwtBearerOptions> configureOptions)
    {
        return builder.AddPekJwtBearer(authenticationScheme, null, configureOptions);
    }

    public static AuthenticationBuilder AddPekJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<PekJwtBearerOptions> configureOptions)
    {
        //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<PekJwtBearerOptions>, JwtBearerConfigureOptions>());
        //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<PekJwtBearerOptions>, JwtBearerPostConfigureOptions>());
        return builder.AddScheme<PekJwtBearerOptions, PekJwtBearerHandler>(authenticationScheme, displayName, configureOptions);
    }
}
