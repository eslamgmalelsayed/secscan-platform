# مراجعة تقنية — SecScan (الحالة بتاريخ 2026-10-22)

- **المرجع:** commit `d8404bb` على `main`
- **المنهج:** قراءة كل الكود، ثم بناء وتشغيل الاختبارات والـ smoke فعليًا على Windows / Node 24، ثم كتابة probes مستقلة لتأكيد كل ملاحظة جوهرية قبل تسجيلها.
- **الهدف المعلن:** يشتغل محليًا بحيث أختبر مواقعي وأحسّن.

## 1. الحكم العام

التصميم الفكري ممتاز والكود نظيف ومنضبط: بوابة نطاق إجبارية في مكان واحد (`GuardedClient`)، تطبيع قبل المقارنة، شرط التكرار قبل التأكيد، سجل append-only، تقرير ثنائي اللغة بإخلاء مسؤولية. ده أعلى من مستوى أغلب الأدوات في نفس المرحلة.

لكن فيه فجوة بين «المواصفة» و«ما يشتغل فعلًا»:

| الادعاء في `implementation-notes` | الواقع المُتحقق منه |
|---|---|
| «مفيش نتيجة بدون تحقق» (§3.5) | **محرك الصلاحيات يطلّع IDOR مؤكد (high/confirmed) على endpoint آمن** (ملاحظة 2.1) |
| «المنصة جاهزة للاستهلاك عبر الـ API» | **الـ API لا يستطيع تشغيل فحص مصادَق إطلاقًا**: لا يوجد أي مسار لإدخال كوكي/توكن حساب الاختبار (ملاحظة 2.2) |
| «إثبات ملكية آلي + توقيع المالك + موافقة أدمن» | الثلاثة **أعلام في الذاكرة يقلبها أي شخص** يرسل JSON فيه `actor: "admin"` — لا يوجد DNS TXT ولا OTP ولا مصادقة على الـ API (ملاحظة 2.3) |
| `npm run build --workspaces` | **يفشل على checkout نظيف** لأن الترتيب أبجدي و`shared` تُبنى آخرًا (ملاحظة 3.1) |

الخلاصة: **البنية صح، لكن المسار من «عندي موقع» إلى «عندي تقرير حقيقي» غير موجود بعد.** التوصية: أسبوع واحد مركّز على ملاحظات القسم 2 + CLI محلي (القسم 4) قبل أي ميزة جديدة.

## 2. ملاحظات حرجة (مرتبة بالأثر)

### 2.1 إيجابية كاذبة «مؤكدة» في محرك الصلاحيات — أخطر ملاحظة

> **الحالة: تم الإصلاح (2026-10-22)** — `normalize.ts` يحتفظ بالمعرّفات في JSON، و`identifier.ts` + `authzDiff.ts` يشترطان معرّف كائن قبل تصنيف bola_idor/cross_tenant؛ العبور بين الأدوار بلا معرّف يذهب لطابور المراجعة كـ `likely`. اختبارات: `normalize.test.ts` + 4 حالات جديدة في `authzDiff.test.ts`.

**الموقع:** `packages/engine/src/normalize.ts` + `authzDiff.ts`

`normalizeBody` يستبدل **كل** UUID و**كل** timestamp في الجسم بـ `<UUID>` / `<TS>` بغض النظر عن المفتاح. النتيجة: ردّان لمستخدمَين مختلفَين على `GET /api/me` (نفس الخطة، نفس الدور، يختلفان فقط في `id` و`created_at`) يصبحان **متطابقَين** بعد التطبيع → `AuthorizationDiffer` يعتبر أن bob حصل على ردّ alice → **`AC-bola_idor` بدرجة high/confirmed** على endpoint آمن تمامًا.

تحققت منه بتشغيل `runAccessControlScan` على sender يعيد لكل جلسة ملفّها الشخصي فقط:

```
3b SECURE /me endpoint reported as: [ 'AC-bola_idor-… [high/confirmed]' ]
```

ده يكسر القاعدة غير القابلة للتفاوض رقم 5، وهو بالضبط نوع الخطأ اللي المواصفة سمّته «ARTEMIS class».

**الإصلاح المقترح (حتمي، بلا LLM):**
1. لا تمسح UUID/TS من القيم إلا تحت مفاتيح متقلبة معروفة؛ المعرّفات الكيانية (`id`, `user_id`, `owner`, `email`…) **يجب** أن تبقى في المقارنة.
2. أضف شرطًا ثالثًا للتأكيد: ردّ المتحدّي يجب أن يطابق baseline المالك **ويختلف** عن ردّ المتحدّي على «مورده هو» (self-baseline). لو bob يحصل على نفس الشيء سواء طلب مورد alice أو مورده، فالمورد إما عام أو «per-session» وليس IDOR.
3. اطلب أن يحتوي الطلب على معرّف كائن (segment رقمي/UUID أو param يشبه id) قبل تصنيفه `bola_idor`؛ المسارات بلا معرّف (`/me`, `/profile`, `/dashboard`) تذهب لـ `needs_review` على الأكثر.

### 2.2 الـ API لا يستطيع تشغيل فحص مصادَق

**الموقع:** `packages/api/src/http/main.ts` → `createHttpSender()` بدون `store`، ولا يوجد أي endpoint أو env var يملأ `SecretStore`.

كل `identity.sessionRef` يُحلّ إلى مادة فارغة → كل الهويات فعليًا anonymous → baseline المالك يرجع 401 → `looksAuthorized=false` → **صفر نتائج بصمت**. الاختبارات تمر لأنها تحقن `Sender` وهمي يقرأ `sessionRef` مباشرة.

**الإصلاح:** مسار إدخال أسرار حسابات الاختبار (ملف JSON محلي أو `POST /identities` يُخزَّن في الذاكرة فقط ولا يُسجَّل)، و`SecretStore` واحد مشترك يُحقن في `createHttpSender`.

### 2.3 سلسلة التفويض كلها honor-system

- `actor` يأتي من جسم الطلب (`actorOf(body)`)؛ `adminApprove` لا يتحقق أن الفاعل أدمن.
- `recordOwnershipVerified` يقلب علمًا فقط؛ لا يوجد كود يتحقق من DNS TXT / http token / meta tag رغم أن `OwnershipProof` enum موجود.
- `ownerSign` يقبل أي كائن فيه `role: 'system_owner'` بلا OTP ولا إيميل ولا حتى `AuthorizationChainLink.parse`.
- لا توجد مصادقة على الـ API أصلًا، و`app.listen(port, '0.0.0.0')` يربط على كل الواجهات.

**للتشغيل المحلي** ده مقبول مؤقتًا بشرط: اربط على `127.0.0.1`، وسمِّ الوضع صراحة `SECSCAN_DEV_TRUST=true` بحيث يرفض الـ API الإقلاع بدونه حتى لا ينسى أحد إن البوابة مفتوحة. **قبل أي عميل:** تنفيذ تحقق الملكية الفعلي (DNS TXT سهل: `dns.resolveTxt`)، ومصادقة أدمن، وOTP للمالك.

### 2.4 حارس SSRF/DNS-rebinding غير مُفعَّل وغير قابل للتفعيل

- `main.ts` لا يمرّر `resolveHost` → `pointsAtPrivateSpace` يرجع `false` دائمًا.
- واجهة `HostResolver` **متزامنة** (`(host) => string[]`) بينما DNS في Node غير متزامن؛ لا يمكن تنفيذها فعليًا.
- حتى لو نُفِّذت، الفحص منفصل عن الاتصال (TOCTOU): الاسم قد يُحلّ لـ IP عام وقت الفحص ولـ `127.0.0.1` وقت `fetch`.
- `blockPrivateAddresses` مربوط بـ `legalResolved` — قراران مستقلان دُمجا في علم واحد.

**الإصلاح:** اجعل `check` غير متزامن، وحلّ الاسم مرة واحدة، ثم اتصل بالـ IP المحلول (undici `Agent` مع `connect.lookup` مخصص) مع تمرير الـ Host الأصلي. وافصل العلمين.

### 2.5 الفحوصات النشطة تعمل كمجهول فقط

**الموقع:** `packages/checks/src/context.ts` → `safeSend(ctx, req, identity = ANON)` وكل الفحوصات تستخدم الافتراضي.

CORS/open-redirect/SQLi/reflection تُرسَل بلا جلسة. أي endpoint خلف تسجيل دخول يرجع 401 → لا كشف. وCORS بالذات قيمته الحقيقية في الردود **المصادَقة**. يجب إرسال كل probe بهوية `capturedAsRole` الخاصة بالـ flow.

### 2.6 فجوات صامتة في التغطية (لا تظهر في `notTested`)

- flow بـ `capturedAsTenant: null` (وهو **افتراضي مستورد HAR**) مقابل هويات لها tenant → `sameRole` يفشل → المالك يصبح anonymous → **صفر نتائج وصفر تحذيرات**. تحققت: `findings 0 | errors 0 | notTested 0`.
- `SessionRegistry.verifyAll` (§7) موجود ولا يُستدعى من `ScanService`؛ جلسة ميتة = تغطية صفر بصمت.
- حل: أي flow بلا مالك مطابق، وأي جلسة فشل فحص حياتها، يُضاف سطر صريح في `notTested` + تحذير في `errors`.

### 2.7 أخطاء كود مؤكدة

| الملف | الخطأ | الأثر |
|---|---|---|
| `engine/src/scanner.ts:60` | `String(e).startsWith('deny_')` — لكن `String(Error)` = `"ScopeRefused: deny_…"` فالشرط لا يصدق أبدًا | كل رفض نطاق يتكرر في `errors[]` (تحققت: `errors=1, notTested=1`) |
| `engine/src/classifier.ts` | مطابقة substring على **URL كامل** بما فيه الـ query | `/presets` و`?remove_filter=0` → `state_changing` → تُرفض GETs آمنة؛ بينما `GET /approve?id=1` تمر كـ safe |
| `checks/src/active.ts` | العلامة `sxz…` حروف وأرقام فقط | لا يمكن التمييز بين منعكس **مُرمَّز** وغير مُرمَّز؛ العنوان «بدون ترميز» غير دقيق. استخدم علامة تحوي `<>"'` وافحص بقاءها خامًا |
| `checks/src/active.ts` | SQLi بسياق نصي فقط (`'…'`)، ويعيد إرسال baseline لكل param | لا كشف للسياق الرقمي؛ طلبات زائدة |
| `api/src/http/controllers.ts` | `Engagement` و`flows` و`identities` و`link` تُحفَظ بلا `parse` | بيانات فاسدة تنفجر لاحقًا كـ 400 بمعنى غامض |
| `api/src/http/errors.filter.ts` | كل `Error` غير معروف → 400 بنص الرسالة الخام | يخفي 500 حقيقية ويسرّب تفاصيل داخلية |
| `prisma/schema.prisma` | `Finding.type` غير موجود في zod، و`cvss`/`retests` غير موجودة في Prisma | انحراف مخطط سيظهر عند أول adapter |

## 3. تشغيل محلي — ما وجدته فعليًا

### 3.1 البناء
`npm run build` (root) **يفشل** على checkout نظيف: الترتيب أبجدي → `engine`/`report` تُبنى قبل `shared`. الحل الفوري في `package.json`:

```json
"build": "npm run build -w @secscan/shared -w @secscan/engine -w @secscan/checks -w @secscan/importers -w @secscan/report -w @secscan/workers -w @secscan/api"
```

(أو TypeScript project references مع `tsc -b`.)

### 3.2 ما نجح بعد البناء بالترتيب
- 50 اختبار vitest: **كلها تمر**.
- 7 فحوصات smoke HTTP: **كلها تمر**.
- Node 24.17 / npm 11 / Docker 29 متوفرون؛ `docker-compose.yml` سليم لكن **لا شيء يستخدمه** بعد (لا Prisma adapter ولا BullMQ adapter).

### 3.3 التبعيات
`npm audit`: 10 ثغرات (3 critical) في `@nestjs/platform-fastify@10` / `fastify` / `@fastify/middie` / `vitest@3`. بما أن المواصفة تعتبر المنصة نفسها «هدفًا عالي القيمة» (§3.6)، الترقية لـ NestJS 12 / vitest 5 مطلوبة قبل أي تعريض للشبكة. محليًا غير حرجة.

### 3.4 ملاحظة على الـ working tree
ملفّا المواصفات في `docs/specs/` **محذوفان في working tree** (غير مُلتزَم). إن كان عن قصد فلا بأس، وإلا `git checkout -- docs/specs`.

## 4. المسار الأقصر لهدفك: «أختبر مواقعي محليًا»

اليوم، لتفحص موقعًا واحدًا عبر الـ API تحتاج 7 طلبات HTTP يدوية **ومع ذلك لن تحصل على فحص مصادَق** (2.2). المقترح، بالترتيب:

1. **أصلح 2.1 أولًا** (الإيجابية الكاذبة) — لا معنى لتقرير لا تثق فيه.
2. **CLI محلي** في `packages/cli` يلتف حول `buildCore` مباشرة بلا HTTP:
   ```bash
   secscan scan --host mysite.com --root https://mysite.com \
     --har customer.har --role customer --tenant t1 \
     --identities identities.json   # {"customer/t1":{"cookies":{"sid":"…"}}, …}
     --out report.ar.md
   ```
   يولّد grant + ownership + sign + approve داخليًا تحت علم `--dev-trust` (يطبع تحذيرًا صريحًا)، يملأ `SecretStore` من الملف، يستدعي `verifyAll`، ثم `ScanService.run`، ثم يكتب التقرير بالعربية والإنجليزية. ده يحوّل الدورة من «ساعة إعداد» إلى «أمر واحد».
3. **أصلح 2.5 و2.6** حتى تظهر النتائج خلف تسجيل الدخول وتظهر الفجوات بدل الصمت.
4. **حد معدّل بسيط + مهلة إجمالية** (§8): `--rps 5` افتراضيًا، وزر إيقاف = Ctrl+C يكتب ما اكتُشف حتى الآن.
5. **معمل محلي بثغرات مقصودة** (مثلًا OWASP Juice Shop أو crAPI في Docker) كـ benchmark ثابت لقياس precision/recall — مطلوب أصلًا في §12.
6. بعدها فقط: Prisma adapter (حتى تُعاد الفحوصات وتُقارن عبر الزمن)، ثم BullMQ، ثم الواجهة.

## 5. ملاحظات أصغر (تحسينات)

- الفحوصات السلبية الخمس تطلب `rootUrl` خمس مرات؛ اطلبه مرة وشاركه.
- `tlsRedirect` و`HSTS` على root بـ `http://` (معمل محلي) ينتجان ضجيجًا دائمًا؛ تخطَّهما حين يكون root غير https.
- `cookies()` يقرأ `set-cookie` واحدًا؛ استخدم `resp.headers.getSetCookie()` في الـ sender وأعد مصفوفة.
- `secretsInResponse` يفحص HTML الجذر فقط؛ اتبع `<script src>` من نفس الأصل.
- `VOLATILE_JSON_KEY` يطابق snake_case فقط (`updated_at`) ولا يطابق `updatedAt`.
- `fingerprintSecret` افتراضي `'change-me'` — ارفض الإقلاع بدونه خارج وضع dev.
- `ScanTelemetry` (§10) موجود ولا يُستخدم؛ اربطه بعدّاد الطلبات في `GuardedClient` حتى يكون «التكلفة لكل نتيجة مؤكدة» رقمًا حقيقيًا من اليوم الأول.
- `ScansController.run` متزامن داخل طلب HTTP؛ مقبول محليًا، لكن اجعل الـ CLI هو المسار الأساسي الآن بدل الـ API.
