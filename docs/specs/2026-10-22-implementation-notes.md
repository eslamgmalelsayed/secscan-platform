# ملاحظات التنفيذ — الحزم والربط بالمواصفة

- **التاريخ:** 2026-10-22
- **الحالة:** الطبقات الأساسية مبنية ومختبرة
- **المرجع:** `docs/specs/2026-10-21-platform-design.md`

## الحزم المبنية (monorepo، TypeScript + zod + vitest)

| الحزمة               | الدور                                                                                                                 | المواصفة               | اختبارات                |
| -------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------- | ----------------------- |
| `@secscan/shared`    | أنواع `Finding`/`Engagement`/`ReportInput` (zod)، ملخصات، **CVSS v3.1**، **ربط الأطر** (ECC/OWASP/CWE/ASVS/ISO/NIST)  | §9                     | 10                      |
| `@secscan/engine`    | البوابة والـ scope والتصنيف والتطبيع، authz-diff، transport، sessions، telemetry، scanner                             | §3/§6/§7/§8/§9/§10/§11 | 24                      |
| `@secscan/importers` | HAR + OpenAPI → flows                                                                                                 | §11                    | 3                       |
| `@secscan/report`    | تقرير AR/EN من `ReportInput`                                                                                          | §9                     | 3                       |
| `@secscan/checks`    | Scorecard سلبي + فحوصات إعداد آمنة (CORS/open-redirect) + كشف نشط غير مدمّر (reflection/SQLi) + JWT، بـ CVSS وربط أطر | §5/§9                  | 2                       |
| `@secscan/api`       | دورة حياة التفويض، سجل append-only، بوابة المعمل (§3.2)، فحص مُبوَّب = authz + checks، تقارير — + طبقة NestJS/Fastify | §3/§6/§8/§9            | 5 vitest + 7 HTTP smoke |
| `@secscan/workers`   | منطق Discovery/Scan/Validator على واجهة Queue                                                                         | §4                     | 3                       |

**الإجمالي:** 50 اختبار vitest + 7 HTTP smoke.

## مبدأ الاختبار: قوي وغير مدمّر

الفحوصات النشطة **كشفية غير مدمّرة بالتصميم** (§8 قاعدة #4): علامات حميدة للانعكاس، وفروق قراءة للـ SQLi (boolean/error) — **بدون payload استغلال، بدون سحب بيانات، بدون عمليات مدمّرة**. الانعكاس (XSS مرشّح) يذهب دائمًا لطابور المراجعة البشرية؛ الـ SQLi المنطقي المؤكَّد بالتكرار يُعتمد. الأفعال المغيّرة للحالة تبقى ممنوعة إلا على staging بإذن صريح. دمج أدوات الاستغلال الثقيلة (sqlmap-style) يبقى لوثيقة المحرك المنفصلة مع شريك أمني (§4).

## ما الذي يحتاج تشغيل فعلي (infra) — لم يُربط بعد

- **Postgres:** المخطط في `prisma/schema.prisma`. مستودعات `@secscan/api` الحالية in-memory وتنفّذ نفس الواجهات؛ محوّل Prisma هو خطوة النشر (`prisma migrate` مقابل قاعدة حية).
- **Redis + BullMQ:** منطق الـ workers مكتوب على واجهة `Queue` مع `InMemoryQueue` للاختبار؛ محوّل BullMQ فوق Redis هو خطوة النشر.
- **`@secscan/web` (Nuxt):** لوحات العميل/الأدمن/المختبر لسه ما اتبنتش — الـ API جاهز للاستهلاك.
- **محرك الفحص النشط (أدوات SQLi/XSS…):**

## التشغيل محلياً

```bash
npm install
npm run build --workspaces
npm run test  --workspaces         # 42 vitest
npm run build -w @secscan/api && npm run smoke -w @secscan/api   # 7 HTTP checks
# API: SECSCAN_LEGAL_RESOLVED=false SECSCAN_LAB_HOSTS=lab.internal npm run start -w @secscan/api
```

## تحديث 2026-10-22 (مساءً) — ردّ على المراجعة

- **فحص على الطابور (gap 1):** `POST /scans` يتحقق من الشروط فورًا (التفويض، قفل المعمل، ووجود الـ engagement) ثم — لو `SECSCAN_REDIS_URL` مضبوط — يُرجع `queued` ويضع المهمة على BullMQ؛ عملية العامل `npm run start:worker -w @secscan/api` تشغّلها وتنقل الحالة queued → running → done. العامل يحمّل ملف الهويات بنفسه، فالأسرار لا تمر عبر Redis (المهمة تحمل مفاتيح الهويات فقط). بدون Redis، الفحص يعمل داخل الـ API كما كان.
- **إيقاف (gap 3):** `POST /scans/:id/stop` يرفع علامة إيقاف مشتركة (Redis عبر العمليات، أو في الذاكرة)؛ الفحص الجاري يستطلعها ويُجهض الـ paced sender وتُحفظ نتائج جزئية مع ملاحظة.
- **وجود الـ engagement (gap 5):** يُرفض الفحص فورًا لو الـ engagement غير موجود، بدل الفشل لاحقًا عند التقرير.
- **إعادة الاختبار (gap 4):** `POST /scans/:id/findings/:findingId/retest` يعيد تشغيل الفحص ويكتب النتيجة (fixed/still_open) في تاريخ `retests` للثغرة.
- **حزمة الأدلة (gap 7):** `GET /scans/:id/evidence` تُرجع JSON كامل (الـ engagement، النتائج بأدلتها، ما لم يُفحص) بجانب تقرير Markdown.
- **الواجهة:** صفحة النتائج تستطلع الفحص المُطابور حتى يكتمل وفيها زر إيقاف؛ العميل يرسل Bearer ومساري توقيع المالك.
- **CI/lint (gap 6):** `.github/workflows/ci.yml` يبني ويفحص الأنواع ويشغّل الاختبارات مقابل حاويتي Postgres و Redis والـ smoke على كل push؛ `npm run lint` = فحص أنواع لكل الحزم (`scripts/typecheck.mjs`).

**لم يُتحقق منه في حاوية التطوير** (محجوب: Postgres/Redis/الشبكة الخارجية): مسار BullMQ/Redis الفعلي، تخزين Postgres الحي، وتشغيل فعلي على موقع تملكه. المنطق مُختبَر عبر الطابور في الذاكرة ووحدات الاختبار؛ التحقق الحقيقي يتم على جهازك أو في CI.

### تشغيل وضع الطابور محليًا
```
npm run services:up && npm run db:migrate
# terminal 1 (API):
DATABASE_URL=… SECSCAN_REDIS_URL=redis://127.0.0.1:6379 SECSCAN_LAB_HOSTS=… \
SECSCAN_IDENTITIES_FILE=identities.json SECSCAN_FINGERPRINT_SECRET=… npm run start -w @secscan/api
# terminal 2 (worker): نفس المتغيرات
… npm run start:worker -w @secscan/api
```

### أول تشغيل على موقع تملكه (gap/next 4)
1. `SECSCAN_LEGAL_RESOLVED=true` و`SECSCAN_LAB_HOSTS` يحوي نطاقك (أو اتركه مقفولًا على المعمل).
2. أنشئ grant لنطاقك، وأثبت الملكية (DNS TXT / well-known / meta)، ووقّع المالك بالرمز على بريد في نطاق الهدف، ثم اعتمد.
3. حمّل حسابات الاختبار في `SECSCAN_IDENTITIES_FILE`، استورد الـ flows، وشغّل الفحص. هذا هو الاختبار الوحيد للاتصال المثبّت (undici) ومعالجة الهويات مقابل خادم حقيقي.
