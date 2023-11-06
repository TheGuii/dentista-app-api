using DentistaApi.Data;
using DentistaApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DentistaApi.Services;

public class AuthService : IAuthService{
    public AuthService( IConfiguration configuration)
    {

        this.configuration = configuration;
    }

    public async Task<IAuthService.IReturn<string>> Login(UserInfo user)
    {
        User? usuario = FindByUser(user);        

        if (usuario == null)
            return new Return<string>(EReturnStatus.Error, null,
                "Login não existe.");

        if (!ValidaSenha(usuario, user))
            return new Return<string>(EReturnStatus.Error, null,
                "Senha inválida.");

        string token = GenerateToken(usuario);

        return new Return<string>(EReturnStatus.Success, usuario, token);
    }

    private  User FindByUser(UserInfo user)
    {
        User? usuario = db.Pacientes.FirstOrDefault(x => x.Login == user.Login);

        if (usuario == null)
        {
            usuario =  db.Dentistas.FirstOrDefault(x => x.Login == user.Login);
        }
        if (usuario == null)
        {
            usuario =  db.Administrador.FirstOrDefault(x => x.Login == user.Login);
        }        
        return usuario;
    }
    private bool ValidaSenha(User user, UserInfo userInfo)
    {
        if(user.Senha == userInfo.GerarHash())
            return true;
        return false;

    }


    //private string GenerateToken(User usuario)
    //{
    //    try
    //    {
    //        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"));
    //        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    //        var claims = new[]
    //        {
    //            new Claim(ClaimTypes.Name, usuario.Nome)
    //        };

    //        var token = new JwtSecurityToken(
    //            issuer: "DentistaAPI",
    //            audience: "DentistaApp",
    //            claims: claims,
    //            expires: DateTime.UtcNow.AddHours(6), 
    //            signingCredentials: credentials
    //        );

    //        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    //        return tokenString;

    //    }
    //    catch (Exception ex)
    //    {
    //        return ex.InnerException.ToString();
    //    }


    //}

    //private SecurityTokenDescriptor GetTokenDescriptor()
    //{
    //    var authSigningKey = new SymmetricSecurityKey( Encoding.UTF8.GetBytes("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"));
    //    var credentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256);

    //    return new SecurityTokenDescriptor
    //    {
    //        Issuer = "DentistaAPI",
    //        Audience = "DentistaApp",
    //        Expires = DateTime.UtcNow.AddMinutes(60),
    //        SigningCredentials = credentials           
    //    };
    //}
    private string GenerateToken(User usuario)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, usuario.Nome),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        var token = tokenHandler.CreateToken(GetTokenDescriptor(claims));
        return tokenHandler.WriteToken(token);
    }

    private SecurityTokenDescriptor GetTokenDescriptor(IEnumerable<Claim> claims)
    {
        var authSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(configuration["JWT:Secret"] ?? "")
        );
        return new SecurityTokenDescriptor
        {
            Issuer = configuration["JWT:Issuer"],
            Audience = configuration["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(600000),
            SigningCredentials = new SigningCredentials(authSigningKey,
                                            SecurityAlgorithms.HmacSha256),
            Subject = new ClaimsIdentity(claims)
        };
    }

    private readonly AppDbContext db = new();
    private readonly IConfiguration configuration;
    public class Return<T> : IAuthService.IReturn<T>
    {
        public Return(EReturnStatus status, User usuario, T result)
        {
            Status = status;
            Result = result;
            Usuario = usuario;
        }

        public EReturnStatus Status { get; private set; }
        public T Result { get; private set; }
        public User Usuario { get; private set; }

        
    }
}
