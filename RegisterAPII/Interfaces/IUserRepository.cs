using RegisterAPII.Models;

namespace RegisterAPII.Interfaces
{
    public interface IUserRepository
    {
        Task<User?> GetUserByEmailAsync(string email);
        Task<User?> GetUserByResetTokenAsync(string token); 
        Task AddUserAsync(User user);
        Task SaveChangesAsync();
    }
}
