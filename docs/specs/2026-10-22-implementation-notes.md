# ملاحظات التنفيذ — الحزم والربط بالمواصفة

- **التاريخ:** 2026-10-22
- **الحالة:** الطبقات الأساسية مبنية ومختبرة
- **المرجع:** `docs/specs/2026-10-21-platform-design.md`

## الحزم المبنية (monorepo، TypeScript + zod + vitest)

| الحزمة | الدور | المواصفة | اختبارات |
|---|---|---|---|
| `@secscan/shared` | أنواع `Finding`/`Engagement`/`ReportInput` (zod) وأدوات الملخص | §9 | 4 |
| `@secscan/engine` | البوابة والـ scope والتصنيف والتطبيع، authz-diff، transport، sessions، telemetry، scanner | §3/§6/§7/§8/§9/§10/§11 | 24 |
| `@secscan/importers` | HAR + OpenAPI → flows | §11 | 3 |
| `@secscan/report` | تقرير AR/EN من `ReportInput` | §9 | 3 |
| `@secscan/api` | دورة حياة التفويض، سجل append-only، بوابة المعمل (§3.2)، تشغيل فحص مُبوَّب، تقارير — + طبقة NestJS/Fastify | §3/§6/§8/§9 | 5 vitest + 7 HTTP smoke |
| `@secscan/workers` | منطق Discovery/Scan/Validator على واجهة Queue | §4 | 3 |

**الإجمالي:** 42 اختبار vitest + 7 HTTP smoke.

## القواعد غير القابلة للتفاوض — أين تُطبَّق في الكود

1. **مفيش فحص نشط بدون تفويض** → `AuthorizationService.assertScanAllowed` (ملكية مثبتة + توقيع المالك + موافقة أدمن + grant حي)، و`ScanService` بيستدعيها قبل أي طلب.
2. **القفل على المعمل قبل حسم القانون (§3.2)** → `LabPolicy`: أي هدف برّه allow-list المعمل مرفوض (`LabPolicyError`)، وبيتفحص لكل هدف grant ولكل host في الـ flows.
3. **كل طلب صادر يعدّي على بوابة** → `GuardedClient` + `ScopeGuard` في المحرك؛ مفيش transport بيتكلم شبكة إلا من خلاله.
4. **غير مدمّر افتراضياً** → `classifier` + رفض `deny_state_changing` ما لم يسمح الـ grant صراحةً.
5. **مفيش نتيجة بدون تحقق** → `AuthorizationDiffer` يتطلب مرجع مجهول + تكرار ناجح مرتين؛ الأقل من الحد → طابور مراجعة.
6. **سجل التفويض append-only** → `AppendOnlyAuditLog` (append + read فقط).

## ما الذي يحتاج تشغيل فعلي (infra) — لم يُربط بعد

- **Postgres:** المخطط في `prisma/schema.prisma`. مستودعات `@secscan/api` الحالية in-memory وتنفّذ نفس الواجهات؛ محوّل Prisma هو خطوة النشر (`prisma migrate` مقابل قاعدة حية).
- **Redis + BullMQ:** منطق الـ workers مكتوب على واجهة `Queue` مع `InMemoryQueue` للاختبار؛ محوّل BullMQ فوق Redis هو خطوة النشر.
- **`@secscan/web` (Nuxt):** لوحات العميل/الأدمن/المختبر لسه ما اتبنتش — الـ API جاهز للاستهلاك.
- **محرك الفحص النشط (أدوات SQLi/XSS…):** مؤجّل عمداً لوثيقة منفصلة مع شريك أمني (§4). المبني هنا هو اختبار الصلاحيات الحتمي الذي تملكه المنصة.

## التشغيل محلياً

```bash
npm install
npm run build --workspaces
npm run test  --workspaces         # 42 vitest
npm run build -w @secscan/api && npm run smoke -w @secscan/api   # 7 HTTP checks
# API: SECSCAN_LEGAL_RESOLVED=false SECSCAN_LAB_HOSTS=lab.internal npm run start -w @secscan/api
```
