WEBHOOK_SECRET = "fixture-secret-must-not-appear-in-output"

@app.post("/hooks/provider")
def receive_webhook(request):
    return apply_event(request.json)
