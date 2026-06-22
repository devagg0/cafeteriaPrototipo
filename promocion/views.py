from rest_framework import viewsets

from producto.views import IsAdmin, IsAuthenticatedJWT, JWTAuthentication

from .models import Promocion
from .serializers import PromocionSerializer


class PromocionViewSet(viewsets.ModelViewSet):
    queryset = Promocion.objects.prefetch_related('productos', 'categorias')
    serializer_class = PromocionSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]
