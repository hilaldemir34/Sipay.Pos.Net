using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Concrete
{
    public class User
    {
        public string App_Id { get; set; }
        public byte[] App_SecretSalt { get; set; }
        public byte[] App_SecretHash { get; set; }
        public List<OperationClaim> Claims { get; set; }   
        
    }
}
