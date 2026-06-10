from django.http import HttpResponse
from django.db import connection
from django.utils.html import escape

def get_user_safe(request):
    user_id = request.GET.get("id")
    cursor = connection.cursor()
    # Safe: using parameterized arguments
    cursor.execute("SELECT * FROM auth_user WHERE id = %s", [user_id])
    user = cursor.fetchone()
    # Safe: escaping HTML entities
    html = "<h1>User: %s</h1>" % escape(user[1])
    return HttpResponse(html)
