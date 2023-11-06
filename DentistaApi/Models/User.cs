using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using DentistaApi.Models.Utils;

namespace DentistaApi.Models
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int? Id { get; set; }
        [Required]        
        public string Nome { get; set; } = "";
        [Required]        
        public string Email { get; set; } = "";
        [Required]        
        public string Login { get; set; } = "";
        [Required]       
        public string Senha { get; set; } = "";
        [Required]        
        public string Telefone { get; set; } = "";
        [Required]        
        public string Cpf { get; set; } = "";        
        public DateOnly DataCadastro { get; set; } = new DateOnly(new DateTime().Year, new DateTime().Month, new DateTime().Day);
        public bool Ativo { get; set; } = true;

        public void SetSenhaHash()
        {
            Senha = Senha.GerarHash();
        }
        
    }
}