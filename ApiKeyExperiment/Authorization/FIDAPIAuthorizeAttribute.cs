using System;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;

namespace ApiKeyExperiment.Authorization
{
    public class FIDAPIAuthorizeAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            try
            {
                if (actionContext.Request.Headers.TryGetValues("X-Api-Key", out var apiKeyHeaderValues))
                {
                    var apiKeyHeaderValue = apiKeyHeaderValues.First();

                    var context = new AuthenticationContext();

                    var apiEntry = context.ApiKeys.FirstOrDefault(k => k.Key == apiKeyHeaderValue);
                    if (apiEntry == null)
                    {
                        HandleUnauthorizedRequest(actionContext);
                        return;
                    }

                    // set up a Claim for "scope" (used by ScopeAuthorizeAttribute)
                    var domain = ConfigurationManager.AppSettings["AuthenticationDomain"];
                    var scopeClaim = new Claim("scope", apiEntry.Permissions, "String", domain);

                    var usernameClaim = new Claim(ClaimTypes.Name, apiEntry.Name);

                    var identity = new ClaimsIdentity(new[] { usernameClaim, scopeClaim }, "ApiKey");
                    var principal = new ClaimsPrincipal(identity);

                    Thread.CurrentPrincipal = principal;
                    actionContext.ControllerContext.RequestContext.Principal = principal;
                    return;
                }
            }
            catch (Exception)
            {
                HandleUnauthorizedRequest(actionContext);
            }

            HandleUnauthorizedRequest(actionContext);
        }
    }
}