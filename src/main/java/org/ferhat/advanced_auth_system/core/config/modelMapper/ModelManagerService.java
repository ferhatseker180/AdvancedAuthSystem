package org.ferhat.advanced_auth_system.core.config.modelMapper;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Service;

@Service
public class ModelManagerService implements IModelMapperService{
    private final ModelMapper requestModelMapper;
    private final ModelMapper responseModelMapper;

    public ModelManagerService(ModelMapper requestModelMapper, ModelMapper responseModelMapper) {
        this.requestModelMapper = requestModelMapper;
        this.responseModelMapper = responseModelMapper;

        // Configuration for Request
        this.requestModelMapper.getConfiguration()
                .setAmbiguityIgnored(true)
                .setMatchingStrategy(MatchingStrategies.STANDARD);

        // Configuration for Response
        this.responseModelMapper.getConfiguration()
                .setAmbiguityIgnored(true)
                .setMatchingStrategy(MatchingStrategies.LOOSE);
    }


@Override
    public ModelMapper forRequest() {
        return this.requestModelMapper;
    }

    @Override
    public ModelMapper forResponse() {
        return this.responseModelMapper;
    }
}
