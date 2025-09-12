import requests
import os
from django.conf import settings
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated

from .models import User
from .serializers import UserSerializer


def bad_request(detail: str, field: str = "non_field_error", extra=None):
    payload = {"detail": detail, "code": "invalid_param", "field": field}
    if extra:
        payload["error"] = extra
    return Response(payload, status=status.HTTP_400_BAD_REQUEST)


def forbidden(detail: str, field: str = "user_pk"):
    return Response(
        {"detail": detail, "code": "permission_denied", "field": field},
        status=status.HTTP_403_FORBIDDEN,
    )


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # ✅ 유저 API는 인증 필수

    # ✅ 카카오 로그인 콜백
    @action(detail=False, methods=["get"], url_path="auth/kakao/callback", permission_classes=[])
    def kakao_callback(self, request):
        code = request.query_params.get("code")
        if not code:
            return bad_request("인가 코드(code)가 필요합니다", "code")

        token_url = "https://kauth.kakao.com/oauth/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": os.environ.get("KAKAO_CLIENT_ID"),
            "redirect_uri": os.environ.get("KAKAO_REDIRECT_URI"),
            "code": code,
        }
        kakao_secret = os.environ.get("KAKAO_CLIENT_SECRET")
        if kakao_secret:
            data["client_secret"] = kakao_secret

        try:
            token_resp = requests.post(token_url, data=data, timeout=5)
            resp_json = token_resp.json()
        except Exception as e:
            return Response(
                {"detail": "카카오 토큰 요청 실패", "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if token_resp.status_code != 200:
            return Response(
                {
                    "detail": "카카오 토큰 교환 실패",
                    "code": "invalid_param",
                    "field": "code",
                    "error": resp_json,
                },
                status=token_resp.status_code,
            )

        kakao_access_token = resp_json.get("access_token")
        if not kakao_access_token:
            return bad_request("access_token 발급 실패", "kakao_access_token", extra=resp_json)

        try:
            headers = {"Authorization": f"Bearer {kakao_access_token}"}
            resp = requests.get("https://kapi.kakao.com/v2/user/me", headers=headers, timeout=5)
            user_info = resp.json()
        except Exception as e:
            return Response(
                {"detail": "카카오 사용자 정보 요청 실패", "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if resp.status_code != 200:
            return bad_request("카카오 사용자 정보 조회 실패", "kakao_access_token", extra=user_info)

        kakao_id = user_info.get("id")
        kakao_account = user_info.get("kakao_account", {})
        email = kakao_account.get("email") or f"{kakao_id}@kakao-user.com"

        if not kakao_id:
            return bad_request("카카오 사용자 ID를 가져올 수 없습니다", "kakao_id", extra=user_info)

        try:
            user, _ = User.objects.get_or_create(
                kakao_id=str(kakao_id),
                defaults={"role": None, "is_active": True, "is_staff": False},
            )
        except Exception as e:
            return Response({"detail": "유저 생성 실패", "error": str(e)}, status=500)

        try:
            token, _ = Token.objects.get_or_create(user=user)
        except Exception as e:
            return Response({"detail": "토큰 발급 실패", "error": str(e)}, status=500)

        try:
            user_data = UserSerializer(user).data
        except Exception as e:
            return Response({"detail": "유저 직렬화 실패", "error": str(e)}, status=500)

        return Response({"accessToken": token.key, "user": user_data}, status=200)

    # ✅ 로그아웃
    @action(detail=False, methods=["post"], url_path="auth/kakao/logout")
    def kakao_logout(self, request):
        if request.user.is_authenticated:
            Token.objects.filter(user=request.user).delete()
        return Response({"message": "Logged out successfully."}, status=200)

    # ✅ 본인 role 설정 (id 제거, 토큰으로 식별)
    @action(detail=False, methods=["post"], url_path="me/type", permission_classes=[IsAuthenticated])
    def set_role_self(self, request):
        user = request.user
        role = request.data.get("role")

        if role not in ["artist", "space"]:
            return bad_request("role은 'artist' 또는 'space'만 가능합니다.", "role")

        user.role = role
        user.save()

        return Response({
            "id": user.id,
            "kakao_id": user.kakao_id,
            "role": user.role,
            "phone_number": user.phone_number,
            "created_at": user.created_at,
        })

    # ✅ 전체 유저 조회 (관리용)
    @action(detail=False, methods=["get"], url_path="all", permission_classes=[IsAuthenticated])
    def list_all_users(self, request):
        users = User.objects.all().order_by("-created_at")
        data = UserSerializer(users, many=True).data
        return Response(data)
