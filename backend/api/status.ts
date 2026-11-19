import { handler } from '../src/http';
import { getStatus } from '../src/service';

export default handler('GET', () => getStatus());
