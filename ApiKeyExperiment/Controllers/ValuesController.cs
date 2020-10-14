using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Http;
using System.Web.Http.Controllers;
using ApiKeyExperiment.Authorization;

namespace ApiKeyExperiment.Controllers
{
    [FIDAPIAuthorize]
    [RoutePrefix("api/values")]
    public class ValuesController : ApiController
    {
        // GET api/values
        [ScopeAuthorize("dis_read")]
        public IEnumerable<string> Get()
        {
            return new[] { ActionContext.ControllerContext.RequestContext.Principal.Identity.Name, "value2" };
        }

        // GET api/values/5
        public string Get(int id)
        {
            return $"value={id}";
        }

        // POST api/values
        [ScopeAuthorize("manage_keys")]
        public IHttpActionResult Post([FromBody] ApiKey newKey)
        {
            var context = new AuthenticationContext();

            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                byte[] secretKeyByteArray = new byte[32]; //256 bit
                cryptoProvider.GetBytes(secretKeyByteArray);
                newKey.Key = Convert.ToBase64String(secretKeyByteArray);
            }

            context.ApiKeys.AddOrUpdate(newKey);
            context.SaveChanges();

            return Ok(newKey);
        }

        [ScopeAuthorize("manage_keys")]
        [Route("updatePermissions")]
        public IHttpActionResult UpdatePermissions([FromBody] ApiKey key)
        {
            var context = new AuthenticationContext();
            var existingKey = context.ApiKeys.FirstOrDefault(k => k.Id == key.Id);
            if (existingKey == null) return NotFound();

            existingKey.Permissions = key.Permissions;
            context.SaveChanges();

            return Ok(existingKey.Permissions);
        }

        // DELETE api/values/5
        public void Delete(int id)
        {
        }
    }
}
