import { handler } from '../src/http';
import { register } from '../src/service';

export default handler('POST', (body) => register(body));
