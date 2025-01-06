from rest_framework.routers import DefaultRouter

from access.api import HomeViewSet, UserViewSet

router = DefaultRouter()
router.register(r'home', HomeViewSet, basename='home')

router.register(r'auth', UserViewSet, basename='auth')
urlpatterns = router.urls