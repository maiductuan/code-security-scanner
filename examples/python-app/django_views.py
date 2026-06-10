from django.http import HttpResponse
from django.db import connection
from django.utils.safestring import mark_safe

def get_user_vulnerable(request):
    user_id = request.GET.get("id")
    cursor = connection.cursor()
    # SQL Injection via format string in raw SQL execute
    cursor.execute("SELECT * FROM auth_user WHERE id = %s" % user_id)
    user = cursor.fetchone()
    # Reflected XSS via mark_safe on unescaped input
    html = "<h1>User: %s</h1>" % user[1]
    return HttpResponse(mark_safe(html))
