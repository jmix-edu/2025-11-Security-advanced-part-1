package com.company.jmixpmsecurity.security.specific;

import io.jmix.core.accesscontext.SpecificOperationAccessContext;

public class ProjectArchiveContext extends SpecificOperationAccessContext {

    public static final String NAME = "project.archive.context";

    public ProjectArchiveContext() {
        super(NAME);
    }
}
