using System.ComponentModel.DataAnnotations.Schema;

namespace DentistaApi.Models
{
    public class Dentista : User
    {
        public string Role { get; set; } = "dentista";

        [InverseProperty("Dentista")]
        public ICollection<Consulta> Consultas { get; } = new List<Consulta>();
        public DateOnly DataNascimento { get; set; }
        
        public Especialidade? Especialidade { get; set; }

    }
}