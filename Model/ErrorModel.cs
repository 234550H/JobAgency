using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;

namespace WebApplication1.Models
{
    public class ErrorModel : PageModel
    {
        public string? RequestId { get; set; }
        public int? StatusCode { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public void OnGet(int? statusCode)
        {
            StatusCode = statusCode;
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
        }
    }


}
