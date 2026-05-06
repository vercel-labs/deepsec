import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Django views: function-based (`def view(request)`), class-based
 * (`class FooView(View)`), URL routing entries (`path(...)`/`re_path(...)`).
 * Gated on Django detection so it stays dormant on plain-Python repos.
 */
export const pyDjangoViewMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-django-view",
  description: "Django views, urlpatterns, and CBVs — entry points (gated on Django)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["django", "djangorestframework"] },
  examples: [
    `    path("users/", views.user_list, name="users"),`,
    `    re_path(r"^items/(?P<pk>\\d+)/$", views.item_detail),`,
    `class UserListView(ListView):`,
    `class ItemDetail(DetailView):`,
    `class ProfileView(APIView):`,
    `class ArticleViewSet(ModelViewSet):`,
    `def index(request):`,
    `def detail_view(request, pk):`,
    `@csrf_exempt`,
    `@api_view(["GET", "POST"])`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-django-view",
      [
        { regex: /^\s*path\s*\(/m, label: "urlpatterns path()" },
        { regex: /^\s*re_path\s*\(/m, label: "urlpatterns re_path()" },
        {
          regex:
            /^class\s+\w+\s*\([^)]*\b(?:View|TemplateView|ListView|DetailView|FormView|APIView|ViewSet|ModelViewSet|GenericAPIView|CreateView|UpdateView|DeleteView)\b/m,
          label: "class-based view",
        },
        {
          regex: /^def\s+\w+\s*\(\s*request\b/m,
          label: "function-based view (def view(request))",
        },
        { regex: /@csrf_exempt\b/, label: "@csrf_exempt — confirm alternate auth" },
        { regex: /@api_view\s*\(/, label: "DRF @api_view decorator" },
      ],
      content,
    );
  },
};
