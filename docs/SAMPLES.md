# 샘플 데이터

아래 샘플은 문서용 가짜 데이터입니다. 실제 로그나 고객 데이터로 바꾸지 마세요.

## 입력

```text
POST /api/demo/action
Authorization: Bearer 데모토큰값
Cookie: session=데모세션값; theme=light
X-Api-Key: 데모API키값
project=예시프로젝트
owner=샘플담당자
address=예시주소
message=AI 보조 업무에 사용하기 전에 이 텍스트를 마스킹합니다.
```

## 출력 형태 예시

```text
POST /api/demo/action
Authorization: Bearer ******
Cookie: session=******; theme=light
X-Api-Key: ******
project=******
owner=*****
address=****
message=AI 보조 업무에 사용하기 전에 이 텍스트를 마스킹합니다.
```

선택한 분류와 패턴에 따라 마스킹 길이는 달라질 수 있습니다. 중요한 기준은 민감해 보이는 값이 평문으로 복사되지 않는 것입니다.

## 넣으면 안 되는 샘플

- 실제 회사명 또는 고객명
- 실제 개인명
- 실제 주소
- 실제 전화번호
- 실제 이메일 또는 도메인
- 실제 API 키, 토큰, 쿠키, 세션 값
- 비공개 업무 맥락이 포함된 원본 프롬프트
- 운영 도구나 고객 시스템 화면 캡처
