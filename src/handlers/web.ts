import { Env } from '../types';
import { htmlResponse } from '../utils/response';
import { renderWebClientHTML } from '../webclient/page';

export async function handleWebClientPage(request: Request, env: Env): Promise<Response> {
  void request;
  void env;
  return htmlResponse(renderWebClientHTML());
}
