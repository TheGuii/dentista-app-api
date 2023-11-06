namespace DentistaApi.Models
{
    public class Administrador : User
    {
        public string Role { get; set; } = "admin";
    }
}