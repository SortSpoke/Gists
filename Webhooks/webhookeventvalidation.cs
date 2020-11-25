[AllowAnonymous]
[HttpPost, Route("webhook/receive")]
public async Task<IActionResult> ReceiveWebhookAsync()
{
    var signature = Request.Headers["sortspoke-webhook-signature"].FirstOrDefault();
    if(siganture == null){
        // Ignore the webhook as no signature is present
        Console.WriteLine("No signature present on webhook request");
        return Ok();
    }
    
    using var ms = new MemoryStream(512);
    await Request.Body.CopyToAsync(ms);
    var content = ms.ToArray();
    var secretBytes = Encoding.UTF8.GetBytes("my_sortspoke_webhook_secret");
    var hmac = new HMACSHA256(secretBytes);
    var targetSignatureBytes = hmac.ComputeHash(content);
    var targetSignature = BitConverter.ToString(targetSignatureBytes);
    
    if(signature == targetSiganature){
        Console.WriteLine("Payload verified - Proceed in using payload data");
    }
    
    return Ok();
}