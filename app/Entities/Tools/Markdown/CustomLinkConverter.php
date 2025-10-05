<?php

declare(strict_types=1);

namespace BookStack\Entities\Tools\Markdown;

use League\HTMLToMarkdown\Converter\LinkConverter;
use League\HTMLToMarkdown\ElementInterface;

class CustomLinkConverter extends LinkConverter
{
    public function convert(ElementInterface $element): string
    {
        $href  = $element->getAttribute('href');
        $title = $element->getAttribute('title');
        $text  = \trim($element->getValue(), "\t\n\r\0\x0B");

        if ($title !== '') {
            $markdown = '[' . $text . '](' . $href . ' "' . $title . '")';
        } elseif ($href === $text && $this->isValidAutolink($href)) {
            $markdown = '<' . $href . '>';
        } elseif ($href === 'mailto:' . $text && $this->isValidEmail($text)) {
            $markdown = '<' . $text . '>';
        } else {
            if (\stristr($href, ' ')) {
                $href = '<' . $href . '>';
            }

            $markdown = '[' . $text . '](<' . $href . '>)';
        }

        if (! $href) {
            if ($this->shouldStrip()) {
                $markdown = $text;
            } else {
                $markdown = \html_entity_decode($element->getChildrenAsString());
            }
        }

        return $markdown;
    }
}