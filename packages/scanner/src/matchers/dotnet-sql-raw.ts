import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dotnetSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "dotnet-sql-raw",
  description:
    'Raw SQL across .NET DB libraries (ADO.NET SqlCommand, Dapper, EF Core FromSqlRaw) — string concat / interpolation is SQL injection (FromSqlInterpolated parameterizes correctly; only FromSqlRaw with concat or $"..." is unsafe)',
  filePatterns: ["**/*.cs"],
  requires: { tech: ["dotnet"] },
  examples: [
    `var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);`,
    `var cmd = new SqlCommand($"SELECT * FROM users WHERE id = {userId}", conn);`,
    `command.CommandText = "DELETE FROM users WHERE id = " + id;`,
    `command.CommandText = $"UPDATE users SET role = '{role}'";`,
    `var users = connection.Query<User>($"SELECT * FROM users WHERE name = '{name}'");`,
    `connection.Execute("DELETE FROM users WHERE id = " + id);`,
    `var rows = connection.QueryAsync<int>($"SELECT id FROM users WHERE id = {id}");`,
    `var blogs = ctx.Blogs.FromSqlRaw($"SELECT * FROM Blogs WHERE Id = {id}").ToList();`,
    `ctx.Database.ExecuteSqlRaw("DELETE FROM Users WHERE Id = " + id);`,
    // SAFE counter-example: FromSqlInterpolated parameterizes correctly
    `// SAFE: ctx.Blogs.FromSqlInterpolated($"SELECT * FROM Blogs WHERE Id = {id}").ToList();`,
  ],
  match(content, filePath) {
    if (/\/(Tests|UnitTests|IntegrationTests)\//.test(filePath)) return [];

    return regexMatcher(
      "dotnet-sql-raw",
      [
        // ADO.NET
        {
          regex: /\bnew\s+SqlCommand\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'new SqlCommand("..." + concat)',
        },
        {
          regex: /\bnew\s+SqlCommand\s*\(\s*\$"[^"]{0,400}\{/,
          label: 'new SqlCommand($"...{interp}...")',
        },
        {
          regex: /\bcommand\.CommandText\s*=\s*"[^"]{0,400}"\s*\+/,
          label: 'command.CommandText = "..." + concat',
        },
        {
          regex: /\bcommand\.CommandText\s*=\s*\$"[^"]{0,400}\{/,
          label: 'command.CommandText = $"...{interp}..."',
        },
        // Dapper
        {
          regex:
            /\bconnection\.(?:Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QueryFirstAsync|Execute|ExecuteAsync|ExecuteScalar|ExecuteScalarAsync)\s*(?:<[^>]+>)?\s*\(\s*\$"[^"]{0,400}\{/,
          label: 'Dapper connection.Query/Execute with $"...{interp}..."',
        },
        {
          regex:
            /\bconnection\.(?:Query|Execute|ExecuteScalar)\s*(?:<[^>]+>)?\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: "Dapper connection.Query/Execute with string concat",
        },
        // Entity Framework
        {
          regex: /\bFromSqlRaw\s*\(\s*\$"[^"]{0,400}\{/,
          label: 'FromSqlRaw with $"..." — unsafe; use FromSqlInterpolated',
        },
        {
          regex: /\bFromSqlRaw\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: "FromSqlRaw with string concat",
        },
        {
          regex: /\bExecuteSqlRaw\s*\(\s*\$"/,
          label: 'ExecuteSqlRaw with $"..."',
        },
        {
          regex: /\bExecuteSqlRaw\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: "ExecuteSqlRaw with string concat",
        },
        // Generic interpolated SQL
        {
          regex: /\$"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}\{/,
          label: "interpolated SQL string with embedded {expr}",
        },
      ],
      content,
    );
  },
};
