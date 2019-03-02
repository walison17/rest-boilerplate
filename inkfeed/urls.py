from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from accounts.views import UsersViewSet

router = routers.DefaultRouter()
router.register(r'users', UsersViewSet, base_name='user')

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('', include(router.urls)),
    path('', include('accounts.urls', namespace='accounts')),
    path('admin/', admin.site.urls),
]
