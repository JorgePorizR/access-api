from django.contrib.auth import authenticate
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from rest_framework import viewsets, status, serializers
from rest_framework.authtoken.admin import User
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
import requests


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()
    groups = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'username', 'email', 'password', 'groups')

    def get_groups(self, obj):
        return [{"id": group.id, "name": group.name} for group in obj.groups.all()]

class UserFormSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'username', 'email', 'password', 'groups')

    def create(self, validated_data):
        groups = validated_data.pop('groups', [])
        password = validated_data.pop('password')

        user = User.objects.create_user(password=password, **validated_data)

        try:
            user.groups.set(groups)
        except ValidationError:
            raise serializers.ValidationError({"groups": "One or more groups are invalid."})
        return user

    def update(self, instance, validated_data):
        groups = validated_data.pop('groups', None)
        password = validated_data.pop('password', None)

        # Actualizar los campos estándar del usuario
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Si se proporciona una contraseña, actualizarla de manera segura
        if password:
            instance.set_password(password)

        # Guardar los cambios en la instancia del usuario
        instance.save()

        # Actualizar los grupos solo si se proporcionan
        if groups is not None:
            try:
                instance.groups.set(groups)
            except ValidationError:
                raise serializers.ValidationError({"groups": "One or more groups are invalid."})

        return instance


class UserFormClientSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'username', 'email', 'password')

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve']:
            return UserSerializer

        return UserFormSerializer

    def get_permissions(self):
        if self.action == 'registerClient':  # Metodo accesible para todos
            permission_classes = [AllowAny]
        else:  # Métodos restringidos a usuarios autenticados
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

        # Sobrescribiendo métodos del ModelViewSet para identificar al usuario autenticado


    def check_admin_user(self, user):
        if not user.groups.filter(id=1).exists():
            return Response({'detail': 'Not Allowed'}, status=status.HTTP_403_FORBIDDEN)
        return None

    def check_admin_partido(self, user):
        if not user.groups.filter(id=4).exists():
            return Response({'detail': 'Not Allowed'}, status=status.HTTP_403_FORBIDDEN)
        return None

    def list(self, request, *args, **kwargs):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        # Crear el usuario utilizando el serializer
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Guardar el usuario creado en la base de datos
        created_user = serializer.save()

        # Serializar el usuario recién creado
        user_data = UserSerializer(created_user).data

        # Buscar en la lista de grupos del user_data si es cliente
        is_cliente = False
        for group in user_data['groups']:
            if group['id'] == 2:
                is_cliente = True
                break

        if is_cliente:
            billetera_data = {
                "UserId": user_data['id'],
                "FirstName": user_data['first_name'],
                "LastName": user_data['last_name'],
                "Username": user_data['username'],
                "Email": user_data['email'],
            }

            # Obtener el token JWT del usuario autenticado
            token = request.COOKIES.get('access')  # Asegúrate de que la cookie 'access' está presente

            try:
                response = requests.post(
                    "http://localhost:5286/api/Billeteras",
                    json=billetera_data,
                    headers={"Authorization": f"Bearer {token}"}  # Agregar el token JWT al encabezado
                )

                if response.status_code == 201:
                    return Response({
                        "user": user_data,
                        "billetera": response.json()
                    }, status=status.HTTP_201_CREATED)
                else:
                    return Response({
                        "user": user_data,
                        "billetera_error": response.json()
                    }, status=response.status_code)

            except requests.exceptions.RequestException as e:
                return Response({
                    "user": user_data,
                    "billetera_error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "user": user_data,
            }, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        # Obtener el usuario antes de la actualización
        instance = self.get_object()
        previous_groups = set(instance.groups.values_list('id', flat=True))
        previous_username = instance.username

        # Crear el usuario utilizando el serializer
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        # Verificar si el username cambió
        new_username = serializer.validated_data.get('username', instance.username)
        if new_username != previous_username:
            # Verificar si existe otro usuario con el nuevo username
            if User.objects.filter(username=new_username).exclude(id=instance.id).exists():
                return Response(
                    {"error": f"Username '{new_username}' is already in use."},
                    status=status.HTTP_400_BAD_REQUEST
                )

         # Obtener los grupos actualizados
        groups_data = serializer.validated_data.get('groups', None)
        if groups_data is not None:
            updated_groups = set(group.id for group in groups_data)
        else:
            updated_groups = set(instance.groups.values_list('id', flat=True))

        # Guardar el usuario actualizado
        updated_user = serializer.save()

        # Serializar el usuario recién actualizado
        user_data = UserSerializer(updated_user).data

        # Determinar si el grupo "cliente" (id=2) fue eliminado
        was_cliente = 2 in previous_groups
        is_cliente_now = 2 in updated_groups

        # 1. Si el usuario tenía el grupo "cliente" y ahora no lo tiene, borrar la billetera
        if was_cliente and not is_cliente_now:
            token = request.COOKIES.get('access')  # Obtener el token JWT de la cookie

            try:
                response = requests.delete(
                    f"http://localhost:5286/api/Billeteras/{updated_user.id}/User",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if response.status_code != 204:
                    return Response({
                        "user": user_data,
                        "billetera_error": "Wallet could not be deleted"
                    }, status=response.status_code)

            except requests.exceptions.RequestException as e:
                return Response({
                    "user": user_data,
                    "billetera_error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 2. Si el usuario no tenía el grupo "cliente" y ahora lo tiene, crear una billetera
        if not was_cliente and is_cliente_now:
            billetera_data = {
                "UserId": updated_user.id,
                "FirstName": updated_user.first_name,
                "LastName": updated_user.last_name,
                "Username": updated_user.username,
                "Email": updated_user.email,
            }

            token = request.COOKIES.get('access')  # Obtener el token JWT de la cookie

            try:
                response = requests.post(
                    "http://localhost:5286/api/Billeteras",
                    json=billetera_data,
                    headers={"Authorization": f"Bearer {token}"}  # Enviar el token en el header
                )

                if response.status_code != 201:
                    return Response({
                        "user": user_data,
                        "billetera_error": response.json()
                    }, status=response.status_code)

            except requests.exceptions.RequestException as e:
                return Response({
                    "user": user_data,
                    "billetera_error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Si todo fue bien, retornar el usuario actualizado
        return Response(user_data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        user_to_delete = self.get_object()

        # Buscar el usuario con user_to_delete.id
        user = User.objects.get(id=user_to_delete.id)

        is_cliente = False
        for group in user.groups.all():
            if group.id == 2:
                is_cliente = True
                break

        # Eliminar el usuario
        response = super().destroy(request, *args, **kwargs)

        token = request.COOKIES.get('access')


        if is_cliente:
            try:
                response = requests.delete(
                    f"http://localhost:5286/api/Billeteras/{user_to_delete.id}/User",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if response.status_code != 204:
                    return Response({
                        "user_error": "User deleted successfully, but wallet could not be deleted",
                        "billetera_error": response.json()
                    }, status=response.status_code)
                else:
                    return Response({
                        "message": "User deleted successfully",
                    }, status=status.HTTP_200_OK)

            except requests.exceptions.RequestException as e:
                return Response({
                    "user_error": "User deleted successfully, but wallet could not be deleted",
                    "billetera_error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "message": "User deleted successfully",
            }, status=status.HTTP_200_OK)


    @action(detail=False, methods=['post'], url_path='register')
    def registerClient(self, request):
        print(request.data)
        validated_data = UserFormClientSerializer(data=request.data)
        validated_data.is_valid(raise_exception=True)

        first_name = validated_data.validated_data.get('first_name')
        last_name = validated_data.validated_data.get('last_name')
        username = validated_data.validated_data.get('username')
        email = validated_data.validated_data.get('email')
        password = validated_data.validated_data.get('password')

        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=password
        )

        groups = [2]
        user.groups.set(groups)
        user.save()

        serializer = UserSerializer(user)

        billetera_data = {
            "UserId": user.id,
            "FirstName": first_name,
            "LastName": last_name,
            "Username": username,
            "Email": email,
        }

        try:
            response = requests.post(
                "http://localhost:5286/api/Billeteras",
                json=billetera_data,
            )

            if response.status_code == 201:
                return Response({
                    "user": serializer.data,
                    "billetera": response.json()
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "user": serializer.data,
                    "billetera_error": response.json()
                }, status=response.status_code)

        except requests.exceptions.RequestException as e:
            return Response({
                "user": serializer.data,
                "billetera_error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # obtener todos los grupos
    @action(detail=False, methods=['get'], url_path='groups')
    def getGroups(self, request):
        user = request.user

        response = self.check_admin_user(user)
        if response:
            return response

        groups = Group.objects.all()
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    # obtener todos los usuarios en e grupo de cliente
    @action(detail=False, methods=['get'], url_path='clientes')
    def getClientes(self, request):
        user = request.user

        response = self.check_admin_partido(user)
        if response:
            return response

        clientes = User.objects.filter(groups__name='cliente')
        serializer = UserSerializer(clientes, many=True)
        return Response(serializer.data)
