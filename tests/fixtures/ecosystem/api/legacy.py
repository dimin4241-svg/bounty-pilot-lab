@app.post("/v1/withdraw")
def legacy_withdraw(request):
    return process_withdrawal(request.json)
