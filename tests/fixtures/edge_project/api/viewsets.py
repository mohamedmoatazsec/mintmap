from knox.models import AuthToken
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


class SessionViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["post"])
    def renew(self, request):
        instance, token = AuthToken.objects.create(request.user)
        return Response({"token": token})

    def list(self, request):
        return Response([])
