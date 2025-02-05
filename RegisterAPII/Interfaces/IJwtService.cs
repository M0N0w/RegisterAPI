using RegisterAPII.Models;

namespace RegisterAPII.Interfaces
{
    public interface IJwtService
    {
        string GenerateToken(User user);
    }
}
