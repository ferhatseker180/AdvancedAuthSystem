package org.ferhat.advanced_auth_system.core.config.modelMapper;

import org.modelmapper.ModelMapper;

public interface IModelMapperService {

    ModelMapper forRequest();

    ModelMapper forResponse();
}
