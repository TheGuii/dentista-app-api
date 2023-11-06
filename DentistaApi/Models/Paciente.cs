using System.ComponentModel.DataAnnotations.Schema;

namespace DentistaApi.Models
{
    public class Paciente : User
	{

        public string Role { get; set; } = "paciente";
        
        public Endereco? Endereco { get; set; }
        
        public Anamnese? Anamnese { get; set; }
        
        public Responsavel? Responsavel { get; set; }

        [InverseProperty("Paciente")]
        public ICollection<Consulta> Consultas { get; } = new List<Consulta>();

    }
}