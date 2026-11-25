تحديث: إضافة طبقة LLM (Gemini) على الـ Recon Agent

ملفين جداد اتضافوا جوه agents/recon/:
  - llm_planner.py   : بيبعت نتايج nmap/nikto/headers لـ Gemini ويسأله
                        يقترح مسارات إضافية آمنة يتفحصوا (زي /robots.txt)
  - probe_fetch.py   : بيعمل GET بسيط وآمن للمسارات اللي الـ LLM اقترحها

وملف agent.py اتعدل عشان يستدعي الخطوة الجديدة دي بعد الثلاث خطوات
القديمة (nmap/nikto/headers).

مهم:
- لو GEMINI_API_KEY مش موجود في ملف .env بتاعكم، الخطوة دي هتتخطى
  تلقائيًا من غير ما توقف باقي الـ Recon.
- محتاجين تثبّتوا مكتبة google-generativeai:
      pip install google-generativeai
  وتضيفوها في pyproject.toml:
      "google-generativeai"
- لازم يكون عندكم GEMINI_API_KEY في ملف .env في جذر الريبو:
      GEMINI_API_KEY=your_key_here

طريقة التركيب:
1. انسخي الملفات الموجودة هنا (استبدال كامل لفولدر agents/recon/
   اللي عندك بالفعل من قبل كده).
2. تأكدي إن .env فيه GEMINI_API_KEY.
3. ثبّتي المكتبة: pip install google-generativeai
4. شغّلي المشروع عادي — هتلاقي في اللوج خطوة "llm_planner" زيادة.
