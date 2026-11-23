package bench;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marks controllers mounted under the /api/v2 prefix (see WebConfig). */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface V2Api {}
