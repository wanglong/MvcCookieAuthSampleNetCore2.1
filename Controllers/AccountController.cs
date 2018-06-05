using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using MvcCookieAuthSample.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using MvcCookieAuthSample.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace MvcCookieAuthSample.Controllers
{
    public class AccountController : Controller
    {
        private UserManager<ApplicationUser>  _userManager;
        private SignInManager<ApplicationUser> _signInManager;

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if(Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string returnUrl = null)
        {
            if(ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                var indentityUser = new ApplicationUser
                {
                    Email = registerViewModel.Email,
                    UserName = registerViewModel.Email,
                    NormalizedUserName = registerViewModel.Email,
                };

                var identityResult = await _userManager.CreateAsync(indentityUser, registerViewModel.Password);
                if (identityResult.Succeeded)
                {
                    await _signInManager.SignInAsync(indentityUser, new AuthenticationProperties { IsPersistent = true });
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    foreach (var error in identityResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }

            }

            return View();
        }

        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string returnUrl)
        {
            if(ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                if (user == null)
                {

                }

                await _signInManager.SignInAsync(user, new AuthenticationProperties { IsPersistent = true });
                return RedirectToLocal(returnUrl);
            }

            return View();
        }

        public IActionResult MyLogin()
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, "leo"));
            claims.Add(new Claim(ClaimTypes.Role, "admin"));
            var clainIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(clainIdentity));
            return Ok();
        }

        public async Task<IActionResult> Logout()
        {
            //HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            //return Ok();
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index","Home");
        }
    }
}