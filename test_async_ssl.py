import asyncio, ssl

async def test():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.open_connection("google.com", 443, ssl=ctx, server_hostname="google.com")
        ssl_obj = writer.get_extra_info("ssl_object")
        print("Cipher:", ssl_obj.cipher())
        print("Cert Dict Keys:", list(ssl_obj.getpeercert().keys()) if ssl_obj.getpeercert() else "None (None cert)")
        bin_cert = ssl_obj.getpeercert(binary_form=True)
        print("Cert Binary Len:", len(bin_cert) if bin_cert else "None")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print("Error:", e)

asyncio.run(test())
