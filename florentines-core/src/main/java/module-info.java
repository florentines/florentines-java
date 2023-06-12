module software.pando.florentines.core {
    requires software.pando.crypto.nacl;
    requires org.slf4j;
    requires com.grack.nanojson;

    exports io.florentine;
    exports io.florentine.caveat;
}