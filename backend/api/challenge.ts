import { handler } from '../src/http';
import { getChallenge } from '../src/service';

export default handler('GET', () => getChallenge());
