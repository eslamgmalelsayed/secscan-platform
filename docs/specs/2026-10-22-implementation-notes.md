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
