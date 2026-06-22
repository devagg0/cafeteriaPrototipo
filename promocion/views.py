from rest_framework import viewsets
from .models import Promocion
from .serializers import PromocionSerializer
from producto.views import JWTAuthentication, IsAdmin, IsAuthenticatedJWT

class PromocionViewSet(viewsets.ModelViewSet):
    """
    ViewSet para el modelo Promocion.
    Permite el CRUD completo de promociones con el siguiente esquema de permisos:
    - List y Retrieve: Accesible por cualquier usuario autenticado (JWT).
    - Create, Update, Partial Update, Destroy: Restringido a usuarios administradores.
    """
    queryset = Promocion.objects.all().prefetch_related('productos', 'categorias')
    serializer_class = PromocionSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]
