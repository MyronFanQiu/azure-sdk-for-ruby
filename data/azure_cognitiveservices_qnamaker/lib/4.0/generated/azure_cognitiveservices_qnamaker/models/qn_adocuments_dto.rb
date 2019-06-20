# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::CognitiveServices::Qnamaker::V4_0
  module Models
    #
    # List of QnADTO
    #
    class QnADocumentsDTO

      include MsRestAzure

      # @return [Array<QnADTO>] List of answers.
      attr_accessor :qna_documents


      #
      # Mapper for QnADocumentsDTO class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          required: false,
          serialized_name: 'QnADocumentsDTO',
          type: {
            name: 'Composite',
            class_name: 'QnADocumentsDTO',
            model_properties: {
              qna_documents: {
                required: false,
                serialized_name: 'qnaDocuments',
                type: {
                  name: 'Sequence',
                  element: {
                      required: false,
                      serialized_name: 'QnADTOElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'QnADTO'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
