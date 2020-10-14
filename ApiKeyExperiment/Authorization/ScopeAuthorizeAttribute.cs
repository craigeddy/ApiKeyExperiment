using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace ApiKeyExperiment.Authorization
{
    public class ScopeAuthorizeAttribute : AuthorizeAttribute
    {
        private readonly string _scope;

        public ScopeAuthorizeAttribute(string scope)
        {
            _scope = scope;
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);

            // Get the Auth0 domain, in order to validate the issuer
            var domain = ConfigurationManager.AppSettings["AuthenticationDomain"];

            // Get the claim principal
            var principal = actionContext.ControllerContext.RequestContext.Principal as ClaimsPrincipal;

            // Get the scope claim. Ensure that the issuer is for the correct domain
            var scopeClaim = principal?.Claims.FirstOrDefault(c => c.Type == "scope" && c.Issuer == domain);
            if (scopeClaim != null)
            {
                // Split scopes
                var scopes = scopeClaim.Value.ToLower().Split(' ');

                // Succeed if the scope array contains the required scope
                if (scopes.Any(s => s == _scope))
                    return;
            }
            HandleUnauthorizedRequest(actionContext);
        }
    }
}