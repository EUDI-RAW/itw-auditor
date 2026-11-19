import { handler } from '../src/http';
import { assert } from '../src/service';

export default handler('POST', (body) => assert(body));
