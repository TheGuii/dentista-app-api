using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using DentistaApi.Services;
using DentistaApi.Models;

namespace AtletaBackend.Controllers;
[Authorize]
[Route("v1/[controller]")]
[ApiController]
public class UsuarioController : ControllerBase
{
    public UsuarioController(UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        RoleManager<IdentityRole> roleManager, IAuthService authService)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.authService = authService;
        this.roleManager = roleManager;
    }

    [HttpPost("CriarPaciente")]
    public async Task<ActionResult<string>> CreatePacienteUser([FromBody] User model)
    {
        return await CreateUserExecute(model, "Paciente");
    }

    [Authorize(Policy = "Admin")]
    [HttpPost("CriarDentista")]
    public async Task<ActionResult<string>> CreateDentistaUser([FromBody] User model)
    {
        return await CreateUserExecute(model, "Dentista");
    }

    // [Authorize(Policy = "Admin")]
    [HttpPost("CriarAdmin")]
    public async Task<ActionResult<string>> CreateAdminUser([FromBody] User model)
    {
        return await CreateUserExecute(model, "Admin");
    }

    private async Task<ActionResult<string>> CreateUserExecute(User userInfo,
                                                        string roleName = "Member")
    {
        var ret = await authService.Register(userInfo, roleName);

        if (ret.Status == EReturnStatus.Success)
        {
            var retToken = await authService.Login(userInfo);

            if (retToken.Status == EReturnStatus.Success)
                return Ok(retToken.Result);
            else
                return BadRequest(retToken.Result);
        }
        else
            return BadRequest(ret.Result);
    }

    [HttpPost("Login")]
    public async Task<ActionResult<string>> Login([FromBody] User userInfo)
    {
        var retToken = await authService.Login(userInfo);

        if (retToken.Status == EReturnStatus.Success)
            return Ok(retToken.Result);
        else
            return BadRequest(retToken.Result);
    }

    private readonly UserManager<IdentityUser> userManager;
    private readonly RoleManager<IdentityRole> roleManager;
    private readonly SignInManager<IdentityUser> signInManager;
    private readonly IAuthService authService;
}