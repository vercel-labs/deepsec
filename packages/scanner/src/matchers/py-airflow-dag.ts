import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyAirflowDagMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-airflow-dag",
  description: "Airflow DAGs and operators — sensitive prod surface (gated on Airflow)",
  filePatterns: ["**/dags/**/*.py", "**/*.py"],
  requires: { tech: ["airflow"] },
  examples: [
    `dag = DAG("my_dag_id", default_args=default_args, schedule="@daily")`,
    `with DAG('etl_pipeline', start_date=datetime(2024, 1, 1)) as dag:`,
    `bash_command = "echo {{ params.x }}",`,
    `task = BashOperator(task_id="echo", bash_command="echo hi")`,
    `op = PythonOperator(task_id="run", python_callable=run)`,
    `op = DockerOperator(task_id="d", image="python:3.11")`,
    `op = PostgresOperator(task_id="q", sql="SELECT 1")`,
    `op = S3Operator(task_id="upload")`,
    `op = HTTPOperator(task_id="call")`,
    `query = "SELECT * FROM t WHERE d='{{ ds }}'"`,
    `bash_command = f"echo {payload}"`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-airflow-dag",
      [
        { regex: /\bDAG\s*\(\s*['"]/, label: "DAG('id', ...) declaration" },
        { regex: /\b@dag\b\s*\(/, label: "@dag decorator (TaskFlow API)" },
        {
          regex: /\b(?:Bash|Python|Docker|Postgres|S3|HTTP)Operator\s*\(/,
          label: "Operator instantiation (review templated args)",
        },
        { regex: /\{\{\s*[^}]+\s*\}\}/, label: "Jinja template — review for injection" },
        { regex: /\bbash_command\s*=\s*f?['"][^'"]*\{/, label: "bash_command with templating" },
      ],
      content,
    );
  },
};
