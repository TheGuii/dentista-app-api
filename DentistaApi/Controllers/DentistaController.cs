using DentistaApi.Data;
using DentistaApi.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using DentistaApi.Services;

namespace DentistaApi.Controllers;

[ApiController]
[Route("v1/[controller]")]
public class DentistaController : ControllerBase
{
    //     public DentistaController(UserManager<IdentityUser> userManager,
    //         SignInManager<IdentityUser> signInManager,
    //         RoleManager<IdentityRole> roleManager, IAuthService authService)
    //     {
    //         this.userManager = userManager;
    //         this.signInManager = signInManager;
    //         this.authService = authService;
    //         this.roleManager = roleManager;
    //     }


    //     [Authorize(Policy = "Admin")]
    //     [HttpPost("CriarPaciente")]
    //     public async Task<ActionResult<string>> CreatePacienteUser([FromBody] UserInfo model)
    //     {
    //         return await CreateUserExecute(model, "Paciente");
    //     }

    //     private async Task<ActionResult<string>> CreateUserExecute(UserInfo userInfo,
    //                                                         string roleName = "Member")
    //     {
    //         var ret = await authService.Register(userInfo, roleName);

    //         if (ret.Status == EReturnStatus.Success)
    //         {
    //             var retToken = await authService.Login(userInfo);

    //             if (retToken.Status == EReturnStatus.Success)
    //                 return Ok(retToken.Result);
    //             else
    //                 return BadRequest(retToken.Result);
    //         }
    //         else
    //             return BadRequest(ret.Result);
    //     }

    //     [HttpPost("Login")]
    //     public async Task<ActionResult<string>> Login([FromBody] UserInfo userInfo)
    //     {
    //         var retToken = await authService.Login(userInfo);

    //         if (retToken.Status == EReturnStatus.Success)
    //             return Ok(retToken.Result);
    //         else
    //             return BadRequest(retToken.Result);
    //     }


    [HttpGet]
    public ActionResult<IList<Dentista>> Get()
    {

        var dentDentistas = db.Dentistas.ToList();

        return Ok(dentDentistas);
    }

    [HttpGet]
    [Route("{id}")]
    public ActionResult<Dentista> GetById(int id)
    {

        var dentDentista = db.Dentistas.FirstOrDefault(x => x.Id == id);

        return dentDentista == null ? NotFound() : Ok(dentDentista);
    }

    [HttpPost]
    public ActionResult<Dentista> Post(Dentista obj)
    {
        obj.SetSenhaHash();


        db.Dentistas.Add(obj);
        db.SaveChanges();


        return CreatedAtAction(nameof(GetById), new { id = obj.Id }, obj);

    }

    [HttpPut("{id}")]
    public IActionResult Put(int id, Dentista obj)
    {
        if (id != obj.Id)
            return BadRequest();

        db.Dentistas.Update(obj);
        db.SaveChanges();

        return NoContent();
    }

    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        if (db.Dentistas == null)
            return NotFound();

        var obj = db.Dentistas.FirstOrDefault(x => x.Id == id);

        if (obj == null)
            return NotFound();

        db.Dentistas.Remove(obj);
        db.SaveChanges();

        return NoContent();
    }

    private readonly AppDbContext db = new();

    // private readonly UserManager<IdentityUser> userManager;
    // private readonly RoleManager<IdentityRole> roleManager;
    // private readonly SignInManager<IdentityUser> signInManager;
    // private readonly IAuthService authService;
}
