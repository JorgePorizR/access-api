from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response


class HomeViewSet(viewsets.ViewSet):

    @action(
        detail=False, methods=['get'],
        url_path='hola', url_name='hola'
    )
    def hola(self, request):
        return Response({'message': 'Hola mundo!'})